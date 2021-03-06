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

#include <fcntl.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_hexdump.h>
#include <rte_timer.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_jhash.h>
#include "app.h"
#include "pipeline_timer_be.h"
#include "pipeline_cgnapt_be.h"

#define BLURT printf("This is line %d of file %s (function %s)\n",\
						 __LINE__, __FILE__, __func__)
/**
 * @file
 * Pipeline Timer Implementation.
 *
 * Implementation of Pipeline TIMER Back End (BE).
 * Runs on separate timer core.
 *
 */


/**
 * @struct
 * Main Pipeline structure for Timer.
 *
 *
 */


struct pipeline_timer {

	uint32_t dequeue_loop_cnt;//一次循环出队多少个timer

} __rte_cache_aligned;

struct rte_mempool *timer_mempool;//timer池（大小由timer_obj_mempool_count指定）
struct rte_mempool *timer_key_mempool;
static int timer_objs_mempool_count;//timer对象的数目（由n_flows得出）
static int timer_ring_alloc_cnt;
static uint32_t timer_dyn_timeout = 30;//可被配置，用于指定timer过期时间（默认30S）
uint64_t cgnapt_timeout;
uint32_t timer_lcore;//当前pipeline运行的core

uint8_t TIMER_DEBUG;

/**
* Function to enqueue timer objects from CGNAPT
*
* @param egress_key
*  CGNAPT egress key
* @param ingress_key
*  CGNAPT inress key
* @param egress_entry
*  CGNAPT egress entry
* @param ingress_entry
*  CGNAPT ingress entry
* @param p_nat
*  CGNAPT thread main pipeline structure
*/
//添加一个timer-key到timer-ring中
void timer_thread_enqueue(struct pipeline_cgnapt_entry_key *egress_key,
				struct pipeline_cgnapt_entry_key *ingress_key,
				struct cgnapt_table_entry *egress_entry,
				struct cgnapt_table_entry *ingress_entry,
				struct pipeline *p_nat)
{

	struct timer_key *tk_ptr;

	//分配一个空闲的timer_key
	if (rte_mempool_get(timer_key_mempool, (void **)&tk_ptr) < 0) {
		printf("TIMER - Error in getting timer_key alloc buffer\n");
		return;
	}

	//设置其对应的egress_key,ingress_key,设置其对应有实体指针
	//设置其对应的pipeline
	//像之前遇到过的问题，这样实际上比较费内存
	rte_memcpy(&tk_ptr->egress_key, egress_key,
			 sizeof(struct pipeline_cgnapt_entry_key));
	rte_memcpy(&tk_ptr->ingress_key, ingress_key,
			 sizeof(struct pipeline_cgnapt_entry_key));
	tk_ptr->egress_entry = egress_entry;
	tk_ptr->ingress_entry = ingress_entry;
	tk_ptr->p_nat = (struct pipeline *) p_nat;

	if (TIMER_DEBUG == 1) {
		rte_hexdump(stdout, "Egress Key", &tk_ptr->egress_key,
					sizeof(struct pipeline_cgnapt_entry_key));
		rte_hexdump(stdout, "Ingress Key", &tk_ptr->ingress_key,
					sizeof(struct pipeline_cgnapt_entry_key));
		rte_hexdump(stdout, "Egress Entry", &tk_ptr->egress_entry,
					sizeof(struct cgnapt_table_entry));
		rte_hexdump(stdout, "Ingress Entry", &tk_ptr->ingress_entry,
					sizeof(struct cgnapt_table_entry));
	}

	//将tk_ptr入队到timer_ring中
	if (rte_ring_enqueue(timer_ring, (void *)tk_ptr) == -ENOBUFS)
		printf("Ring enqueue failed: trying to enqueue\n");
}

/**
* Function to dequeue timer objects coming from CGNAPT
*
*/
//自timer_ring中取出一个timer_key,然后为其启动定时器
void timer_thread_dequeue(void)
{
	struct timer_key *tk_ptr;
	int ret;

	//自timer_ring中出一个tk_ptr
	ret = rte_ring_dequeue(timer_ring, (void *)&tk_ptr);
	if (ret == -ENOENT)
		return;

	if (TIMER_DEBUG == 1) {
		BLURT;
		rte_hexdump(stdout, "Egress Key", &tk_ptr->egress_key,
					sizeof(struct pipeline_cgnapt_entry_key));
		rte_hexdump(stdout, "Ingress Key", &tk_ptr->ingress_key,
					sizeof(struct pipeline_cgnapt_entry_key));
		rte_hexdump(stdout, "Egress Entry", &tk_ptr->egress_entry,
					sizeof(struct cgnapt_table_entry));
		rte_hexdump(stdout, "Ingress Entry", &tk_ptr->ingress_entry,
					sizeof(struct cgnapt_table_entry));
	}

	#ifdef PCP_ENABLE
	/* To differentiate between PCP req entry and dynamic entry we
	* are using "timeout" value in the table entry
	* timeout is - 1 : static entry
	* timeout is 0  : dynamic entry
	* timeout > 0  : pcp entry
	* timeout is 0 then default cgnapt_timeout value is used
	*/

	//If PCP entry already exits

	if (tk_ptr->egress_entry->data.timer != NULL) {

		if (rte_timer_reset(tk_ptr->egress_entry->data.timer,
			tk_ptr->egress_entry->data.timeout * rte_get_timer_hz(),
			SINGLE, timer_lcore,
			cgnapt_entry_delete,
			tk_ptr) < 0)
		printf("PCP Entry Err : Timer already running\n");


	} else{
	#endif

	struct rte_timer *timer;

	//分配一个timer对象
	if (rte_mempool_get(timer_mempool, (void **)&timer) < 0) {
		printf("TIMER - Error in getting timer alloc buffer\n");
		return;
	}
	//初始化timer的状态
	rte_timer_init(timer);

	#ifdef PCP_ENABLE
		if (tk_ptr->egress_entry->data.timeout > 0)
			tk_ptr->egress_entry->data.timer = timer;
	#endif

	//设置timer的过期时间
	if (rte_timer_reset(
		timer,
		#ifdef PCP_ENABLE
		tk_ptr->egress_entry->data.timeout > 0 ?
		tk_ptr->egress_entry->data.timeout * rte_get_timer_hz() :
		#endif
		cgnapt_timeout,//timer过期时间
		SINGLE,//单次定时器
		timer_lcore,
		cgnapt_entry_delete,//超时回调
		tk_ptr) < 0)
		printf("Err : Timer already running\n");

	#ifdef PCP_ENABLE
	}
	#endif
}

/**
 * Function to delete a NAT entry due to timer expiry
 *
 * @param timer
 *  A pointer to struct rte_timer
 * @param arg
 *  void pointer to timer arguments
 */
//cgnat表项超时回调
void cgnapt_entry_delete(struct rte_timer *timer, void *arg)
{
	int ret = 0;

	struct timer_key *tk_ptr = (struct timer_key *)arg;
	struct pipeline_cgnapt *p_nat = (struct pipeline_cgnapt *)
					tk_ptr->p_nat;

	if (
		#ifdef PCP_ENABLE
		(tk_ptr->egress_entry->data.timeout > 0) ||
		#endif
		((tk_ptr->egress_entry->data.ttl == 1) &&
		(tk_ptr->ingress_entry->data.ttl == 1))) {

		/* call pipeline hash table egress entry delete */
		#ifdef CGNAPT_DEBUGGING
		#ifdef CGNAPT_DBG_PRNT
		printf("\nTimer egr:");
		print_key(&tk_ptr->egress_key);
		#endif
		#endif

		//删除egress
		rte_hash_del_key(napt_common_table,
					&tk_ptr->egress_key);

		/* call pipeline hash table ingress entry delete */
		#ifdef CGNAPT_DEBUGGING
		#ifdef CGNAPT_DBG_PRNT
		printf("\nTimer ing:");
		print_key(&tk_ptr->ingress_key);
		#endif
		#endif

		//删除ingress
		rte_hash_del_key(napt_common_table,
					&tk_ptr->ingress_key);

		p_nat->dynCgnaptCount -= 2;
		p_nat->n_cgnapt_entry_deleted += 2;

		if (is_phy_port_privte(tk_ptr->egress_key.pid)) {
		#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG > 2)
				printf("Deleting port:%d\n",
							 tk_ptr->ingress_key.port);
		#endif

		uint32_t public_ip = tk_ptr->egress_entry->data.pub_ip;

		release_iport(tk_ptr->ingress_key.port, public_ip, p_nat);

		ret = decrement_max_port_counter(tk_ptr->egress_key.ip,
						tk_ptr->egress_key.pid,
						p_nat);

		if (ret == MAX_PORT_DEC_REACHED)
			rte_atomic16_dec(&all_public_ip
				 [rte_jhash(&public_ip, 4, 0) %
					CGNAPT_MAX_PUB_IP].count);

		#ifdef CGNAPT_DBG_PRNT
			if (CGNAPT_DEBUG >= 2) {
				if (ret < 0)
					printf("Max Port hash entry does not "
					"exist: %d\n", ret);
				if (!ret)
					printf("Max Port Deletion entry for "
					"the IP address: 0x%x\n",
					tk_ptr->egress_key.ip);
			}
		#endif
		}

		//timer归还
		rte_timer_stop(timer);
		rte_mempool_put(timer_mempool, timer);
		rte_mempool_put(timer_key_mempool, tk_ptr);//归还timer-key
		return;
	}

	//将ttl修改为1
	if (!tk_ptr->egress_entry->data.ttl)
		tk_ptr->egress_entry->data.ttl = 1;

	if (!tk_ptr->ingress_entry->data.ttl)
		tk_ptr->ingress_entry->data.ttl = 1;

	/*cgnapt_timeout*/
	//重置定时器（延迟删除？）
	rte_timer_reset(timer, cgnapt_timeout, SINGLE,
			timer_lcore, cgnapt_entry_delete, tk_ptr);

}

/*
 * Function to parse the timer pipeline parameters
 *
 * @params p
 *  Timer pipeline structure
 * @params params
 *  Timer pipeline params read from config file
 *
 * @return
 * 0 on success, value on failure
 */
//timer参数解析
static int
pipeline_cgnapt_parse_args(struct pipeline_timer *p,
				 struct pipeline_params *params)
{
	uint32_t dequeue_loop_cnt_present = 0;
	uint32_t n_flows_present = 0;
	uint32_t timer_dyn_timeout_present = 0;
	struct pipeline_timer *p_timer = (struct pipeline_timer *)p;
	uint32_t i;

	if (TIMER_DEBUG > 2) {
		printf("TIMER pipeline_cgnapt_parse_args params->n_args: %d\n",
					 params->n_args);
	}

	for (i = 0; i < params->n_args; i++) {
		char *arg_name = params->args_name[i];
		char *arg_value = params->args_value[i];

		if (TIMER_DEBUG > 2) {
			printf("TIMER args[%d]: %s %d, %s\n", i, arg_name,
						 atoi(arg_value), arg_value);
		}

		//每次循环处理多少个timer_key
		if (strcmp(arg_name, "dequeue_loop_cnt") == 0) {
			if (dequeue_loop_cnt_present)
				return -1;
			dequeue_loop_cnt_present = 1;

			p_timer->dequeue_loop_cnt = atoi(arg_value);
			printf("dequeue_loop_cnt : %d\n",
						 p_timer->dequeue_loop_cnt);
			continue;
		}

		//timer动态的超时时间
		if (strcmp(arg_name, "timer_dyn_timeout") == 0) {
			if (timer_dyn_timeout_present)
				return -1;
			timer_dyn_timeout_present = 1;

			timer_dyn_timeout = atoi(arg_value);
			printf("cgnapt dyn timeout: %d\n", timer_dyn_timeout);
			continue;
		}

		//需要最多支持多少流（流将被放大到2的整数次
		if (strcmp(arg_name, "n_flows") == 0) {
			if(n_flows_present)
				return -1;
			n_flows_present = 1;

			printf("Timer : n_flows = %d\n", atoi(arg_value));
			timer_objs_mempool_count =
					nextPowerOf2(atoi(arg_value));//flows将被增大为2的整数次
			timer_ring_alloc_cnt =
					nextPowerOf2(atoi(arg_value));
			printf("Timer : next power of 2 of n_flows = %d\n",
				timer_ring_alloc_cnt);
		}
	}

	if(!n_flows_present){
		printf("Timer : n_flows is not present\n");
		return -1;
	}


	return 0;
}

//pipeline timer所在core
uint32_t get_timer_core_id(void)
{
	return timer_lcore;
}

/*
 * Function to initialize main Timer pipeline
 *
 * Init Timer pipeline parameters
 * Parse Timer pipline parameters
 *
 * @params params
 *  Timer pipeline parameters read from config file
 * @params arg
 *  Pointer to the app_params structure
 *
 * @return
 * Timer pipeline struct pointer on success , NULL on failue
 */
static void *pipeline_timer_init(struct pipeline_params *params, void *arg)
{
	struct app_params *app = (struct app_params *)arg;
	struct pipeline_timer *p_timer;
	uint32_t size;

	printf("Entering pipeline_timer_init\n");

	/* Check input arguments */
	if (app == NULL)
		return NULL;

	/* Memory allocation */
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct pipeline_timer));
	p_timer = rte_zmalloc(NULL, size, RTE_CACHE_LINE_SIZE);

	if (p_timer == NULL)
		return NULL;

	p_timer->dequeue_loop_cnt = 100;

	timer_lcore = rte_lcore_id();

	//timer参数解析
	if (pipeline_cgnapt_parse_args(p_timer, params))
		return NULL;

	cgnapt_timeout = rte_get_tsc_hz() * timer_dyn_timeout;
	printf("cgnapt_timerout%" PRIu64 "\n", cgnapt_timeout);

	/* Create port alloc buffer */

	//用于分配timer
	timer_mempool = rte_mempool_create("timer_mempool",
						 timer_objs_mempool_count,
						 sizeof(struct rte_timer),
						 0, 0,
						 NULL, NULL,
						 NULL, NULL, rte_socket_id(), 0);
	if (timer_mempool == NULL)
		rte_panic("timer_mempool create error\n");

	//用于分配timer对应的数据
	timer_key_mempool = rte_mempool_create("timer_key_mempool",
								 timer_objs_mempool_count,
								 sizeof(struct timer_key),
								 0, 0,
								 NULL, NULL,
								 NULL, NULL, rte_socket_id(), 0);
	if (timer_key_mempool == NULL)
		rte_panic("timer_key_mempool create error\n");

	//用于管理timer-key的ring
	timer_ring = rte_ring_create("TIMER_RING", timer_ring_alloc_cnt,
			rte_socket_id(), RING_F_SC_DEQ);

	if (timer_ring == NULL)
		rte_panic("timer_ring creation failed");

	return (void *)p_timer;
}

/*
 * Function to free the Timer pipeline
 *
 * @params pipeline
 *  Timer pipeline structure pointer
 *
 * @return
 * 0 on success, Negitive value on failure
 */
static int pipeline_timer_free(void *pipeline)
{
	struct pipeline_master *p = (struct pipeline_master *)pipeline;

	if (p == NULL)
		return -EINVAL;

	rte_free(p);

	return 0;
}

/*
 * Function to run custom code continiously
 *
 * @params pipeline
 *  Timer pipeline structure pointer
 *
 * @return
 * 0 on success, Negitive value on failure
 */
//消费timer_ring中的timer_key,为其启动定时器
static int pipeline_timer_run(void *pipeline)
{
	struct pipeline_timer *p = (struct pipeline_timer *)pipeline;
	uint32_t i;

	if (p == NULL)
		return -EINVAL;
	for (i = 0; i < p->dequeue_loop_cnt; i++)
		timer_thread_dequeue();//启动定时器

	return 0;
}

/*
 * Function to run custom code on pipeline timer expiry
 *
 * @params pipeline
 *  Timer pipeline structure pointer
 *
 * @return
 * 0 on success, Negitive value on failure
 */
//实现timer触发检查
static int pipeline_timer_timer(__rte_unused void *pipeline)
{
	rte_timer_manage();
	return 0;
}

//timer pipeline 后端
struct pipeline_be_ops pipeline_timer_be_ops = {
	.f_init = pipeline_timer_init,
	.f_free = pipeline_timer_free,
	.f_run = pipeline_timer_run,//处理timer_ring中timer_key
	.f_timer = pipeline_timer_timer,
	.f_track = NULL,
};
