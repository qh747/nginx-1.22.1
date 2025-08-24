
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;

struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;
    void                 *data;
    ngx_pool_cleanup_t   *next;
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;

struct ngx_pool_large_s {
    ngx_pool_large_t     *next;
    void                 *alloc;
};


typedef struct {
    u_char               *last;
    u_char               *end;
    ngx_pool_t           *next;
    ngx_uint_t            failed;
} ngx_pool_data_t;


struct ngx_pool_s {
    //                    存储数据
    ngx_pool_data_t       d;

    //                    内存池节点最大可分配内存大小
    size_t                max;

    //                   当前可用的内存池节点
    ngx_pool_t           *current;
    ngx_chain_t          *chain;

    //                   存储大块内存
    ngx_pool_large_t     *large;

    //                   内存释放回调函数
    ngx_pool_cleanup_t   *cleanup;
    ngx_log_t            *log;
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;

/**
 * @brief  创建内存池
 * @return 内存池指针
 * @param  size 内存池大小
 * @param  log  日志
 */
ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);

/**
 * @brief  销毁内存池
 * @param  pool 内存池指针
 */
void ngx_destroy_pool(ngx_pool_t *pool);

/**
 * @brief  重新初始化内存池
 * @param  pool 内存池指针
 */
void ngx_reset_pool(ngx_pool_t *pool);

/**
 * @brief  申请内存，申请首地址按NGX_POOL_ALIGNMENT对齐
 * @return 内存指针
 * @param  pool 内存池指针
 * @param  size 内存大小
 */
void *ngx_palloc(ngx_pool_t *pool, size_t size);

/**
 * @brief  申请内存，申请首地址不对齐
 * @return 内存指针
 * @param  pool 内存池指针
 * @param  size 内存大小
 */
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);

/**
 * @brief  申请内存，申请首地址按NGX_POOL_ALIGNMENT对齐，并初始化
 * @return 内存指针
 * @param  pool 内存池指针
 * @param  size 内存大小
 */
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);

/**
 * @brief  申请大块内存，申请首地址按自定义对齐方式对齐
 * @return 内存指针
 * @param  pool 内存池指针
 * @param  size 内存大小
 */
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);

/**
 * @brief  释放大块内存
 * @return 释放结果
 * @param  pool 内存池指针
 * @param  p 内存指针
 */
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);

/**
 * @brief  添加内存释放回调函数
 * @return 内存释放回调函数指针
 * @param  p 内存池指针
 * @param  size 内存大小
 */
ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);

/**
 * @brief  关闭文件句柄函数
 * @param  p 内存池指针
 * @param  fd 文件描述符
 */
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);

/**
 * @brief  关闭文件句柄函数
 * @param  data ngx_pool_cleanup_file_t类型数据
 */
void ngx_pool_cleanup_file(void *data);

/**
 * @brief  关闭文件句柄函数，并对文件索引减一
 * @param  data ngx_pool_cleanup_file_t类型数据
 */
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
