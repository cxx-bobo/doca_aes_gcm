/*
 * fize size <= 1MB
 *
 */

#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_aes_gcm.h>
#include <doca_error.h>
#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_pe.h>

#include "../../../common.h"
#include "aes_gcm_common.h"

DOCA_LOG_REGISTER(AES_GCM_ENCRYPT);


doca_error_t aes_gcm_encrypt(struct aes_gcm_cfg *cfg, char *file_data, size_t file_size)
{
    struct aes_gcm_resources resources = {0};	//用于保存 AES-GCM 资源的结构体
	struct program_core_objects *state = NULL;	//包含程序核心对象的结构体，包括设备句柄和上下文
	struct doca_buf *src_doca_buf = NULL;	//用于源数据的 DOCA 缓冲区
	struct doca_buf *dst_doca_buf = NULL;	//用于目标数据的 DOCA 缓冲区
	/* The sample will use 2 doca buffers */
	uint32_t max_bufs = 2;	//使用的 DOCA 缓冲区的最大数量
	char *dst_buffer = NULL;	//用于存储加密数据的目标缓冲区
	uint8_t *resp_head = NULL;	//指向响应数据头部的指针
	size_t data_len = 0;
	char *dump = NULL;
	FILE *out_file = NULL;
	struct doca_aes_gcm_key *key = NULL;	//AES-GCM 密钥对象
	doca_error_t result = DOCA_SUCCESS;
	doca_error_t tmp_result = DOCA_SUCCESS;
	uint64_t max_encrypt_buf_size = 0;	//加密任务支持的最大缓冲区大小

	out_file = fopen(cfg->output_path, "w");//覆盖写
	if (out_file == NULL) {
		DOCA_LOG_ERR("Unable to open output file: %s", cfg->output_path);
		return DOCA_ERROR_NO_MEMORY;
	}
	printf("small is%d\n",max_bufs);

    //设置加密模式
    resources.mode = AES_GCM_MODE_ENCRYPT;
    result = allocate_aes_gcm_resources(cfg->pci_address, max_bufs, &resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate AES-GCM resources: %s", doca_error_get_descr(result));
		goto close_file;
	}

    state = resources.state;

	result = doca_aes_gcm_cap_task_encrypt_get_max_buf_size(doca_dev_as_devinfo(state->dev), &max_encrypt_buf_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to query AES-GCM encrypt max buf size: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}
	if (file_size > max_encrypt_buf_size) {
		DOCA_LOG_ERR("File size %zu > max buffer size %zu", file_size, max_encrypt_buf_size);
		goto destroy_resources;
	}

	/* Start AES-GCM context */
	result = doca_ctx_start(state->ctx);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start context: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}

    dst_buffer = calloc(1, max_encrypt_buf_size);
	if (dst_buffer == NULL) {
		result = DOCA_ERROR_NO_MEMORY;
		DOCA_LOG_ERR("Failed to allocate memory: %s", doca_error_get_descr(result));
		goto destroy_resources;
	}

    /*设置 DOCA 内存映射的内存范围
    * state->dst_mmap: DOCA 内存映射结构
    * dst_buffer:要设置的内存范围的起始地址
    */
    result = doca_mmap_set_memrange(state->dst_mmap, dst_buffer, max_encrypt_buf_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}
    /*定义和设置一个内存映射对象所管理的整体内存范围*/
	result = doca_mmap_start(state->dst_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}
	result = doca_mmap_set_memrange(state->src_mmap, file_data, file_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}
	result = doca_mmap_start(state->src_mmap);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
		goto free_dst_buf;
	}

    //用于从缓冲区库存中获取一个 doca_buf，该 doca_buf 指向 doca_mmap 管理的内存范围内的某个具体内存区域
    result =
		doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->src_mmap, file_data, file_size, &src_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s",
			     doca_error_get_descr(result));
		goto free_dst_buf;
	}
	result = doca_buf_inventory_buf_get_by_addr(state->buf_inv,
						    state->dst_mmap,
						    dst_buffer,
						    max_encrypt_buf_size,
						    &dst_doca_buf);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
			     doca_error_get_descr(result));
		goto destroy_src_buf;
	}

    /* 设置缓冲区的数据指针和数据长度 */
	result = doca_buf_set_data(src_doca_buf, file_data, file_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
			     doca_error_get_descr(result));
		goto destroy_dst_buf;
	}

    /* Create DOCA AES-GCM key */
	result = doca_aes_gcm_key_create(resources.aes_gcm, cfg->raw_key, cfg->raw_key_type, &key);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Unable to create DOCA AES-GCM key: %s", doca_error_get_descr(result));
		goto destroy_dst_buf;
	}

    /* Record start time */
    struct timespec start_time, current_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    /* Variables to track total data processed */
    size_t total_data_processed = 0;
    double elapsed_time = 0.0;
    /* Loop for 5 seconds */
    while(true){
        DOCA_LOG_INFO("--------------------------in loop--------------------");
        // 重置 src_doca_buf 的数据长度
        result = doca_buf_set_data(src_doca_buf, file_data, file_size);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to set data in src_doca_buf: %s", doca_error_get_descr(result));
            goto destroy_key;
        }

        // 重置 dst_doca_buf 的数据长度为零
        result = doca_buf_reset_data_len(dst_doca_buf);
        if (result != DOCA_SUCCESS) {
            DOCA_LOG_ERR("Unable to reset data length in dst_doca_buf: %s", doca_error_get_descr(result));
            goto destroy_key;
        }

        result = submit_aes_gcm_encrypt_task(&resources,
					     src_doca_buf,
					     dst_doca_buf,
					     key,
					     (uint8_t *)cfg->iv,
					     cfg->iv_length,
					     cfg->tag_size,
					     cfg->aad_size);
	    if (result != DOCA_SUCCESS) {
		    DOCA_LOG_ERR("AES-GCM encrypt task failed: %s", doca_error_get_descr(result));
		    goto destroy_key;
	    }



        /* 更新总处理数据量  */
        doca_buf_get_data_len(dst_doca_buf, &data_len);
        total_data_processed += data_len;

        // /* 释放 doca_buf */
        // doca_buf_dec_refcount(src_doca_buf, NULL);
        // doca_buf_dec_refcount(dst_doca_buf, NULL);

        /* 检查是否已过去5秒 */
        clock_gettime(CLOCK_MONOTONIC, &current_time);
        elapsed_time = (current_time.tv_sec - start_time.tv_sec) +
                       (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
        if (elapsed_time >= 5.0)
            break;

    }

    /* Stop AES-GCM context */
    result = doca_ctx_stop(state->ctx);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to stop context: %s", doca_error_get_descr(result));
        goto destroy_key;
    }

    /* Wait for context to reach IDLE state */
    while (resources.run_pe_progress) {
        if (doca_pe_progress(state->pe) == 0)
            nanosleep(&(struct timespec){0, SLEEP_IN_NANOS}, NULL);
    }

    /* Calculate throughput */
    double throughput = (double)total_data_processed / (1024 * 1024) / elapsed_time; // MB/s
    DOCA_LOG_INFO("Total data processed: %zu bytes", total_data_processed);
    DOCA_LOG_INFO("Elapsed time: %.4f seconds", elapsed_time);
    DOCA_LOG_INFO("Throughput: %.4f MB/s", throughput);

    /*将加密结果写入out.txt文件*/
    doca_buf_get_head(dst_doca_buf, (void **)&resp_head);   //获取缓冲区的起始地址
    doca_buf_get_data_len(dst_doca_buf, &data_len); //获取缓冲区中数据的长度
    fwrite(resp_head, sizeof(uint8_t), data_len, out_file);
    DOCA_LOG_INFO("File was encrypted successfully and saved in: %s", cfg->output_path);
    

destroy_key:
	tmp_result = doca_aes_gcm_key_destroy(key);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy DOCA AES-GCM key: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_dst_buf:
	tmp_result = doca_buf_dec_refcount(dst_doca_buf, NULL);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to decrease DOCA destination buffer reference count: %s",
			     doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
destroy_src_buf:
	tmp_result = doca_buf_dec_refcount(src_doca_buf, NULL);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to decrease DOCA source buffer reference count: %s",
			     doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
free_dst_buf:
	free(dst_buffer);
destroy_resources:
	tmp_result = destroy_aes_gcm_resources(&resources);
	if (tmp_result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to destroy AES-GCM resources: %s", doca_error_get_descr(tmp_result));
		DOCA_ERROR_PROPAGATE(result, tmp_result);
	}
close_file:
	fclose(out_file);

	return result;
    
}



// /*
//  * Run aes_gcm_encrypt sample
//  *
//  * @cfg [in]: Configuration parameters
//  * @file_data [in]: file data for the encrypt task
//  * @file_size [in]: file size
//  * @return: DOCA_SUCCESS on success, DOCA_ERROR otherwise.
//  */
// doca_error_t aes_gcm_encrypt_loop(struct aes_gcm_cfg *cfg, char *file_data, size_t file_size)
// {
// 	struct aes_gcm_resources resources = {0};	//AES-GCM 所需的资源，包括上下文、设备等
// 	struct program_core_objects *state = NULL;	//程序的核心对象，包含：doca_dev、doca_mmap(src_buf、dst_buf)、doca_buf_inventory、doca_ctx、doca_pe
// 	struct doca_buf *src_doca_buf = NULL;	//源 DOCA 缓冲区
// 	struct doca_buf *dst_doca_buf = NULL;	//目标 DOCA 缓冲区
// 	/* The sample will use 2 doca buffers */
// 	uint32_t max_bufs = 2;	//DOCA 缓冲区的最大数量
// 	char *dst_buffer = NULL;	//存储加密后的数据的缓冲区
// 	uint8_t *resp_head = NULL;	//指向加密结果的指针
// 	size_t data_len = 0;	//数据长度
// 	char *dump = NULL;	//用于存储十六进制格式的加密数据字符串
// 	FILE *out_file = NULL;	//输出文件的文件指针
// 	struct doca_aes_gcm_key *key = NULL;	//AES-GCM 密钥对象
// 	doca_error_t result = DOCA_SUCCESS;	//用于错误处理的变量
// 	doca_error_t tmp_result = DOCA_SUCCESS;	//用于错误处理的变量
// 	uint64_t max_encrypt_buf_size = 0;	//AES-GCM 加密任务支持的最大缓冲区大小

// 	out_file = fopen(cfg->output_path, "wr");
// 	if (out_file == NULL) {
// 		DOCA_LOG_ERR("Unable to open output file: %s", cfg->output_path);
// 		return DOCA_ERROR_NO_MEMORY;
// 	}

// 	/* Allocate resources */
// 	resources.mode = AES_GCM_MODE_ENCRYPT;
// 	result = allocate_aes_gcm_resources(cfg->pci_address, max_bufs, &resources);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to allocate AES-GCM resources: %s", doca_error_get_descr(result));
// 		goto close_file;
// 	}

// 	state = resources.state;

// 	result = doca_aes_gcm_cap_task_encrypt_get_max_buf_size(doca_dev_as_devinfo(state->dev), &max_encrypt_buf_size);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to query AES-GCM encrypt max buf size: %s", doca_error_get_descr(result));
// 		goto destroy_resources;
// 	}

// 	if (file_size > max_encrypt_buf_size) {
// 		DOCA_LOG_ERR("File size %zu > max buffer size %zu", file_size, max_encrypt_buf_size);
// 		goto destroy_resources;
// 	}

// 	/* Start AES-GCM context   应该是全局的 与task无关*/
// 	result = doca_ctx_start(state->ctx);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to start context: %s", doca_error_get_descr(result));
// 		goto destroy_resources;
// 	}


// 	/*--------------------------------------------------------------------------------------------*/
// 	dst_buffer = calloc(1, max_encrypt_buf_size);
// 	if (dst_buffer == NULL) {
// 		result = DOCA_ERROR_NO_MEMORY;
// 		DOCA_LOG_ERR("Failed to allocate memory: %s", doca_error_get_descr(result));
// 		goto destroy_resources;
// 	}

// 	result = doca_mmap_set_memrange(state->dst_mmap, dst_buffer, max_encrypt_buf_size);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
// 		goto free_dst_buf;
// 	}
// 	result = doca_mmap_start(state->dst_mmap);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
// 		goto free_dst_buf;
// 	}

// 	result = doca_mmap_set_memrange(state->src_mmap, file_data, file_size);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to set mmap memory range: %s", doca_error_get_descr(result));
// 		goto free_dst_buf;
// 	}

// 	result = doca_mmap_start(state->src_mmap);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to start mmap: %s", doca_error_get_descr(result));
// 		goto free_dst_buf;
// 	}

// 	/* Construct DOCA buffer for each address range */
// 	result =
// 		doca_buf_inventory_buf_get_by_addr(state->buf_inv, state->src_mmap, file_data, file_size, &src_doca_buf);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing source buffer: %s",
// 			     doca_error_get_descr(result));
// 		goto free_dst_buf;
// 	}

// 	/* Construct DOCA buffer for each address range */
// 	result = doca_buf_inventory_buf_get_by_addr(state->buf_inv,
// 						    state->dst_mmap,
// 						    dst_buffer,
// 						    max_encrypt_buf_size,
// 						    &dst_doca_buf);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
// 			     doca_error_get_descr(result));
// 		goto destroy_src_buf;
// 	}

// 	/* Set data length in doca buffer */
// 	result = doca_buf_set_data(src_doca_buf, file_data, file_size);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Unable to acquire DOCA buffer representing destination buffer: %s",
// 			     doca_error_get_descr(result));
// 		goto destroy_dst_buf;
// 	}

// 	/* Create DOCA AES-GCM key */
// 	result = doca_aes_gcm_key_create(resources.aes_gcm, cfg->raw_key, cfg->raw_key_type, &key);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Unable to create DOCA AES-GCM key: %s", doca_error_get_descr(result));
// 		goto destroy_dst_buf;
// 	}

// 	/* Submit AES-GCM encrypt task */
// 	//注意放任务进去的时候要注意检查 task数量是否达到上限 doca_aes_gcm_cap_get_max_num_tasks 需要检查吗？
// 	result = submit_aes_gcm_encrypt_task(&resources,
// 					     src_doca_buf,
// 					     dst_doca_buf,
// 					     key,
// 					     (uint8_t *)cfg->iv,
// 					     cfg->iv_length,
// 					     cfg->tag_size,
// 					     cfg->aad_size);
// 	if (result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("AES-GCM encrypt task failed: %s", doca_error_get_descr(result));
// 		goto destroy_key;
// 	}

// 	/* Write the result to output file */
// 	doca_buf_get_head(dst_doca_buf, (void **)&resp_head);
// 	doca_buf_get_data_len(dst_doca_buf, &data_len);
// 	fwrite(resp_head, sizeof(uint8_t), data_len, out_file);
// 	DOCA_LOG_INFO("File was encrypted successfully and saved in: %s", cfg->output_path);

// 	/* Print destination buffer data */
// 	dump = hex_dump(resp_head, data_len);
// 	if (dump == NULL) {
// 		DOCA_LOG_ERR("Failed to allocate memory for printing buffer content");
// 		result = DOCA_ERROR_NO_MEMORY;
// 		goto destroy_key;
// 	}

// 	DOCA_LOG_INFO("AES-GCM encrypted data:\n%s", dump);
// 	free(dump);

// destroy_key:
// 	tmp_result = doca_aes_gcm_key_destroy(key);
// 	if (tmp_result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to destroy DOCA AES-GCM key: %s", doca_error_get_descr(tmp_result));
// 		DOCA_ERROR_PROPAGATE(result, tmp_result);
// 	}
// destroy_dst_buf:
// 	tmp_result = doca_buf_dec_refcount(dst_doca_buf, NULL);
// 	if (tmp_result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to decrease DOCA destination buffer reference count: %s",
// 			     doca_error_get_descr(tmp_result));
// 		DOCA_ERROR_PROPAGATE(result, tmp_result);
// 	}
// destroy_src_buf:
// 	tmp_result = doca_buf_dec_refcount(src_doca_buf, NULL);
// 	if (tmp_result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to decrease DOCA source buffer reference count: %s",
// 			     doca_error_get_descr(tmp_result));
// 		DOCA_ERROR_PROPAGATE(result, tmp_result);
// 	}
// free_dst_buf:
// 	free(dst_buffer);
// destroy_resources:
// 	tmp_result = destroy_aes_gcm_resources(&resources);
// 	if (tmp_result != DOCA_SUCCESS) {
// 		DOCA_LOG_ERR("Failed to destroy AES-GCM resources: %s", doca_error_get_descr(tmp_result));
// 		DOCA_ERROR_PROPAGATE(result, tmp_result);
// 	}
// close_file:
// 	fclose(out_file);

// 	return result;
// }
