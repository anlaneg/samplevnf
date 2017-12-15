/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_pipeline.h>

#include "pipeline_common_be.h"
#include "app.h"
#include "thread.h"

#if APP_THREAD_HEADROOM_STATS_COLLECT

#define PIPELINE_RUN_REGULAR(thread, pipeline)		\
do {							\
	uint64_t t0 = rte_rdtsc_precise();		\
	int n_pkts = rte_pipeline_run(pipeline->p);	\
							\
	if (n_pkts == 0) {				\
		uint64_t t1 = rte_rdtsc_precise();	\
							\
		thread->headroom_cycles += t1 - t0;	\
	}						\
} while (0)


#define PIPELINE_RUN_CUSTOM(thread, data)		\
do {							\
	uint64_t t0 = rte_rdtsc_precise();		\
	int n_pkts = data->f_run(data->be);		\
							\
	if (n_pkts == 0) {				\
		uint64_t t1 = rte_rdtsc_precise();	\
							\
		thread->headroom_cycles += t1 - t0;	\
	}						\
} while (0)

#else

#define PIPELINE_RUN_REGULAR(thread, pipeline)		\
	rte_pipeline_run(pipeline->p)

#define PIPELINE_RUN_CUSTOM(thread, data)		\
	data->f_run(data->be)

#endif

uint32_t exit_app_thread = 0;

//收取消息
static inline void *
thread_msg_recv(struct rte_ring *r)
{
	void *msg;
	int status = rte_ring_sc_dequeue(r, &msg);

	if (status != 0)
		return NULL;

	return msg;
}

static inline void
thread_msg_send(struct rte_ring *r,
	void *msg)
{
	int status;

	do {
		status = rte_ring_sp_enqueue(r, msg);
	} while (status == -ENOBUFS);
}

static int
thread_pipeline_enable(struct app_thread_data *t,
		struct thread_pipeline_enable_msg_req *req)
{
	struct app_thread_pipeline_data *p;

	if (req->f_run == NULL) {
		if (t->n_regular >= APP_MAX_THREAD_PIPELINES)
			return -1;
	} else {
		if (t->n_custom >= APP_MAX_THREAD_PIPELINES)
			return -1;
	}

	p = (req->f_run == NULL) ?
		&t->regular[t->n_regular] :
		&t->custom[t->n_custom];

	p->pipeline_id = req->pipeline_id;
	p->be = req->be;
	p->f_run = req->f_run;
	p->f_timer = req->f_timer;
	p->timer_period = req->timer_period;
	p->deadline = 0;

	if (req->f_run == NULL)
		t->n_regular++;
	else
		t->n_custom++;

	return 0;
}

static int
thread_pipeline_disable(struct app_thread_data *t,
		struct thread_pipeline_disable_msg_req *req)
{
	uint32_t n_regular = RTE_MIN(t->n_regular, RTE_DIM(t->regular));
	uint32_t n_custom = RTE_MIN(t->n_custom, RTE_DIM(t->custom));
	uint32_t i;

	/* search regular pipelines of current thread */
	for (i = 0; i < n_regular; i++) {
		if (t->regular[i].pipeline_id != req->pipeline_id)
			continue;

		if (i < n_regular - 1)
			memcpy(&t->regular[i],
				&t->regular[i+1],
				(n_regular - 1 - i) * sizeof(struct app_thread_pipeline_data));

		n_regular--;
		t->n_regular = n_regular;

		return 0;
	}

	/* search custom pipelines of current thread */
	for (i = 0; i < n_custom; i++) {
		if (t->custom[i].pipeline_id != req->pipeline_id)
			continue;

		if (i < n_custom - 1)
			memcpy(&t->custom[i],
				&t->custom[i+1],
				(n_custom - 1 - i) * sizeof(struct app_thread_pipeline_data));

		n_custom--;
		t->n_custom = n_custom;

		return 0;
	}

	/* return if pipeline not found */
	return -1;
}

static int
thread_msg_req_handle(struct app_thread_data *t)
{
	void *msg_ptr;
	struct thread_msg_req *req;
	struct thread_msg_rsp *rsp;

	msg_ptr = thread_msg_recv(t->msgq_in);
	req = msg_ptr;
	rsp = msg_ptr;

	if (req != NULL)
		switch (req->type) {
		case THREAD_MSG_REQ_PIPELINE_ENABLE: {
			rsp->status = thread_pipeline_enable(t,
					(struct thread_pipeline_enable_msg_req *) req);
			thread_msg_send(t->msgq_out, rsp);
			break;
		}

		case THREAD_MSG_REQ_PIPELINE_DISABLE: {
			rsp->status = thread_pipeline_disable(t,
					(struct thread_pipeline_disable_msg_req *) req);
			thread_msg_send(t->msgq_out, rsp);
			break;
		}

		case THREAD_MSG_REQ_HEADROOM_READ: {
			struct thread_headroom_read_msg_rsp *rsp =
				(struct thread_headroom_read_msg_rsp *)
				req;

			rsp->headroom_ratio = t->headroom_ratio;
			rsp->status = 0;
			thread_msg_send(t->msgq_out, rsp);
			break;
		}
		default:
			break;
		}

	return 0;
}

static void
thread_headroom_update(struct app_thread_data *t, uint64_t time)
{
	uint64_t time_diff = time - t->headroom_time;

	t->headroom_ratio =
		((double) t->headroom_cycles) / ((double) time_diff);

	t->headroom_cycles = 0;
	t->headroom_time = rte_rdtsc_precise();
}

int
app_thread(void *arg)
{
	//获取当前服务本线程的core,取对应线程数据
	struct app_params *app = (struct app_params *) arg;
	uint32_t core_id = rte_lcore_id(), i, j;
	struct app_thread_data *t = &app->thread_data[core_id];

	for (i = 0; ; i++) {
		uint32_t n_regular = RTE_MIN(t->n_regular, RTE_DIM(t->regular));
		uint32_t n_custom = RTE_MIN(t->n_custom, RTE_DIM(t->custom));

		if (exit_app_thread)
			break;

		/* Run regular pipelines */
		//regular类型的run(即用户未指定pipeline的run函数）
		for (j = 0; j < n_regular; j++) {
			struct app_thread_pipeline_data *data = &t->regular[j];
			struct pipeline *p = data->be;

			PIPELINE_RUN_REGULAR(t, p);
		}

		/* Run custom pipelines */
		//custom类型的run(用䚮指定了pipeline的run函数）
		for (j = 0; j < n_custom; j++) {
			struct app_thread_pipeline_data *data = &t->custom[j];

			//调用用户自定义的run
			PIPELINE_RUN_CUSTOM(t, data);
		}

		/* Timer */
		//优化:每隔16次循环检查一次if(time < t->deadline)
		if ((i & 0xF) == 0) {
			uint64_t time = rte_get_tsc_cycles();
			uint64_t t_deadline = UINT64_MAX;

			if (time < t->deadline)
				//用于辅助每隔deadline间隔执行一次
				continue;

			//下面这两段可以抽取一个函数来简化代码。
			/* Timer for regular pipelines */
			for (j = 0; j < n_regular; j++) {
				struct app_thread_pipeline_data *data =
					&t->regular[j];
				uint64_t p_deadline = data->deadline;

				if (p_deadline <= time) {
					//已过期，执行其timer函数
					data->f_timer(data->be);
					//设置下次执行时间
					p_deadline = time + data->timer_period;
					data->deadline = p_deadline;
				}

				//取下次执行时间点
				if (p_deadline < t_deadline)
					t_deadline = p_deadline;
			}

			/* Timer for custom pipelines */
			for (j = 0; j < n_custom; j++) {
				struct app_thread_pipeline_data *data =
					&t->custom[j];
				uint64_t p_deadline = data->deadline;

				if (p_deadline <= time) {
					//已过期，执行其timer函数
					data->f_timer(data->be);
					//设置下次执行时间
					p_deadline = time + data->timer_period;
					data->deadline = p_deadline;
				}

				//取下次执行时间点
				if (p_deadline < t_deadline)
					t_deadline = p_deadline;
			}

			/* Timer for thread message request */
			{
				uint64_t deadline = t->thread_req_deadline;

				if (deadline <= time) {
					//线程消息请求处理延迟过期，开始消息请求处理
					thread_msg_req_handle(t);
					thread_headroom_update(t, time);
					deadline = time + t->timer_period;
					t->thread_req_deadline = deadline;
				}

				//取下次执行时间点
				if (deadline < t_deadline)
					t_deadline = deadline;
			}

			//设置系统下次的deadline
			t->deadline = t_deadline;
		}
	}

	return 0;
}
