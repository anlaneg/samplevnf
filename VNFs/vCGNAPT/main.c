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

#include "app.h"

static struct app_params app;

int
main(int argc, char **argv)
{
	//log初始化
	rte_openlog_stream(stderr);

	/* Config */
	//初始化默认配置（缺省配置）
	app_config_init(&app);

	//命令行解析
	app_config_args(&app, argc, argv);

	//如果需要预处理，则采用app->preproc对配置文件进行预处理，生成app->parser_file
	app_config_preproc(&app);

	//配置文件解析（读取配置文件，完成pipeline，eal,txq等规定段的常规识别）
	app_config_parse(&app, app.parser_file);

	app_config_check(&app);//配置检查

	/* Timer subsystem init*/
	rte_timer_subsystem_init();

	/* Init */
	app_init(&app);

	/* Run-time */
	//各core均执行app_thread,包括master core
	rte_eal_mp_remote_launch(
		app_thread,
		(void *) &app,
		CALL_MASTER);

	return 0;
}
