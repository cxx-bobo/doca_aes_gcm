#include <stdlib.h>
#include <string.h>

#include <doca_argp.h>  //用于命令行参数解析
#include <doca_aes_gcm.h>   //AES-GCM 加密功能的 API
#include <doca_dev.h>   //DOCA 设备管理
#include <doca_error.h> //错误处理
#include <doca_log.h>   //日志功能

#include <utils.h>
#include <time.h>

#include "aes_gcm_common.h"

#include <openssl/rand.h>

DOCA_LOG_REGISTER(AES_GCM_ENCRYPT::MAIN);

/* 声明加密函数*/
doca_error_t aes_gcm_encrypt(struct aes_gcm_cfg *cfg, char *file_data, size_t file_size);

void generateRandomDataToFile(size_t size, const char* filePath) {
    // 动态分配数组来存储随机数据
    unsigned char* data = (unsigned char*)malloc(size);
    if (data == NULL) {
        fprintf(stderr, "Memory allocation failed.\n");
        exit(EXIT_FAILURE);
    }
    // 生成随机数据
    if (RAND_bytes(data, size) != 1) {
        fprintf(stderr, "Failed to generate random data.\n");
        free(data);  // 释放内存
        exit(EXIT_FAILURE);
    }
    // 打开文件进行写操作
    FILE* file = fopen(filePath, "wb");
    if (file == NULL) {
        fprintf(stderr, "Failed to open file: %s\n", filePath);
        free(data);
        exit(EXIT_FAILURE);
    }
    // 将随机数据写入文件
    size_t written = fwrite(data, 1, size, file);
    if (written != size) {
        fprintf(stderr, "Failed to write all data to file.\n");
        fclose(file);
        free(data);
        exit(EXIT_FAILURE);
    }
    // 关闭文件并释放内存
    fclose(file);
    free(data);
    printf("Successfully generated %zu bytes of random data to %s\n", size, filePath);
}


size_t parseSize(const char* sizeStr) {
    size_t multiplier = 1;
    char* numEnd;

    // 使用 strtoul 来解析数字部分
    size_t size = strtoul(sizeStr, &numEnd, 10);

    // 检查解析后的单位部分
    if (strcmp(numEnd, "B") == 0) {
        multiplier = 1;
    } else if (strcmp(numEnd, "KB") == 0 || strcmp(numEnd, "K") == 0) {
        multiplier = 1024;
    } else if (strcmp(numEnd, "MB") == 0 || strcmp(numEnd, "M") == 0) {
        multiplier = 1024 * 1024;
    } else if (strcmp(numEnd, "GB") == 0 || strcmp(numEnd, "G") == 0) {
        multiplier = 1024 * 1024 * 1024;
    } else {
        fprintf(stderr, "Invalid size format. Use <number>B, <number>K, <number>M, or <number>G.\n");
        exit(EXIT_FAILURE); // 退出程序，指示错误
    }

    return size * multiplier;
}

int main(int argc, char **argv)
{
    doca_error_t result;    //用于存储函数的返回值，判断是否出现错误。
    struct aes_gcm_cfg aes_gcm_cfg; //AES-GCM 配置结构体
    char *file_data = NULL; //指向读取的文件数据的指针
    size_t file_size;   //文件大小
    struct doca_log_backend *sdk_log;   //DOCA 日志后端，用于记录 SDK 内部的日志
    int exit_status = EXIT_FAILURE; //程序的退出状态，初始化为 EXIT_FAILURE，表示默认情况下程序失败退出。

	/* 注册日志后端 */
    result = doca_log_backend_create_standard();
    if (result != DOCA_SUCCESS)
        goto sample_exit;
    /* 注册 SDK 内部的日志后端 */
	result = doca_log_backend_create_with_file_sdk(stderr, &sdk_log);
	if (result != DOCA_SUCCESS)
		goto sample_exit;
	result = doca_log_backend_set_sdk_level(sdk_log, DOCA_LOG_LEVEL_WARNING);
	if (result != DOCA_SUCCESS)
		goto sample_exit;

	DOCA_LOG_INFO("Starting the sample");
    /*初始化 AES-GCM 配置参数 */
	init_aes_gcm_params(&aes_gcm_cfg);
    /*初始化命令行参数解析*/
	result = doca_argp_init("doca_aes_gcm_encrypt", &aes_gcm_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init ARGP resources: %s", doca_error_get_descr(result));
		goto sample_exit;
	}
    /*注册命令行参数*/
	result = register_aes_gcm_params();
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register ARGP params: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}
    /*解析命令行参数*/
	result = doca_argp_start(argc, argv);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to parse sample input: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}

    /*根据输入aes_gcm_cfg.my_fize_size创建随机数据，并写入aes_gcm_cfg.file_path */
    size_t dataSize = parseSize(aes_gcm_cfg.my_file_size);
    generateRandomDataToFile(dataSize,aes_gcm_cfg.file_path);


    /*读取输入文件*/
    result = read_file(aes_gcm_cfg.file_path, &file_data, &file_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to read file: %s", doca_error_get_descr(result));
		goto argp_cleanup;
	}
    /*执行文件加密*/
	result = aes_gcm_encrypt(&aes_gcm_cfg, file_data, file_size);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("aes_gcm_encrypt() encountered an error: %s", doca_error_get_descr(result));
		goto data_file_cleanup;
	}

	exit_status = EXIT_SUCCESS;
    

data_file_cleanup:
	if (file_data != NULL)
		free(file_data);
argp_cleanup:
	doca_argp_destroy();
sample_exit:
	if (exit_status == EXIT_SUCCESS)
		DOCA_LOG_INFO("Sample finished successfully");
	else
		DOCA_LOG_INFO("Sample finished with errors");
	return exit_status;

}
