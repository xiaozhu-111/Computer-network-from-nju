#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
// 前缀树节点结构体
struct TrieNode {
    int port;
    struct TrieNode* child[2];
};

static struct TrieNode* root = NULL;

// 创建新节点
struct TrieNode* create_node() {
    struct TrieNode* node = (struct TrieNode*)malloc(sizeof(struct TrieNode));
    node->port = -1;
    node->child[0] = node->child[1] = NULL;
    return node;
}

// 将一个点分十进制字符串 IP 转换为 uint32_t
static uint32_t ip_str_to_uint(const char* ip_str) {
    uint32_t ip;
    inet_pton(AF_INET, ip_str, &ip);
    return ntohl(ip);
}

// 从 forwarding-table.txt 创建前缀树
void create_tree(const char* fname) {
    root = create_node();
    FILE* fp = fopen(fname, "r");
    if (!fp) return;

    char ip_str[32];
    int mask_len, port;

    while (fscanf(fp, "%s %d %d", ip_str, &mask_len, &port) == 3) {
        uint32_t ip = ip_str_to_uint(ip_str);
        struct TrieNode* node = root;
        for (int i = 31; i >= 32 - mask_len; --i) {
            int bit = (ip >> i) & 1;
            if (!node->child[bit]) node->child[bit] = create_node();
            node = node->child[bit];
        }
        node->port = port;
    }
    fclose(fp);
}

// 查找 IP 所对应的端口
uint32_t* lookup_tree(uint32_t* ip_vec) {
    uint32_t* result = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);
    for (int i = 0; i < TEST_SIZE; ++i) {
        uint32_t ip = ip_vec[i];
        struct TrieNode* node = root;
        int best = -1;
        for (int j = 31; j >= 0 && node; --j) {
            if (node->port != -1) best = node->port;
            int bit = (ip >> j) & 1;
            node = node->child[bit];
        }
        result[i] = best;
    }
    return result;
}

// 从 lookup_file 读取测试数据
uint32_t* read_test_data(const char* lookup_file) {
    FILE* fp = fopen(lookup_file, "r");
    if (!fp) return NULL;

    uint32_t* data = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);
    char ip_str[32];
    int count = 0;

    while (count < TEST_SIZE && fscanf(fp, "%s", ip_str) == 1) {
        data[count++] = ip_str_to_uint(ip_str);
    }
    fclose(fp);
    return data;
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
// uint32_t* read_test_data(const char* lookup_file){
    
// }

// // Constructing an advanced trie-tree to lookup according to `forward_file`
// void create_tree(const char* forward_file){
//     fprintf(stderr,"TODO: %s\n",__func__);
// }

// // Look up the ports of ip in file `lookup_file` using the basic tree
// uint32_t *lookup_tree(uint32_t* ip_vec){
//     fprintf(stderr,"TODO: %s\n",__func__);
//     return NULL;
// }

// 前缀树压缩节点结构体
struct CompressedTrieNode {
    int port;
    int skip_len;  // 压缩跳过的比特数
    struct CompressedTrieNode* child[2];
};

static struct CompressedTrieNode* comp_root = NULL;

// 创建压缩前缀树节点
struct CompressedTrieNode* create_comp_node() {
    struct CompressedTrieNode* node = (struct CompressedTrieNode*)malloc(sizeof(struct CompressedTrieNode));
    node->port = -1;
    node->skip_len = 0;
    node->child[0] = node->child[1] = NULL;
    return node;
}

// 插入压缩前缀树
void insert_compressed(uint32_t ip, int mask_len, int port) {
    struct CompressedTrieNode* node = comp_root;
    int i = 31;
    while (mask_len > 0) {
        int bit = (ip >> i) & 1;

        if (!node->child[bit]) {
            node->child[bit] = create_comp_node();
            node->child[bit]->skip_len = mask_len - 1;
            node->child[bit]->port = port;
            return;
        }

        int skip = node->child[bit]->skip_len;
        i -= skip + 1;
        mask_len -= skip + 1;
        node = node->child[bit];
    }
    node->port = port;
}

void create_tree_advance(const char* fname) {
    comp_root = create_comp_node();
    FILE* fp = fopen(fname, "r");
    if (!fp) return;

    char ip_str[32];
    int mask_len, port;

    while (fscanf(fp, "%s %d %d", ip_str, &mask_len, &port) == 3) {
        uint32_t ip = ip_str_to_uint(ip_str);
        insert_compressed(ip, mask_len, port);
    }
    fclose(fp);
}

uint32_t* lookup_tree_advance(uint32_t* ip_vec) {
    uint32_t* result = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);

    for (int i = 0; i < TEST_SIZE; ++i) {
        uint32_t ip = ip_vec[i];
        struct CompressedTrieNode* node = comp_root;
        int best = -1;
        int j = 31;

        while (node && j >= 0) {
            if (node->port != -1) best = node->port;
            int bit = (ip >> j) & 1;
            node = node->child[bit];
            if (node)
                j -= node->skip_len + 1;
        }
        result[i] = best;
    }
    return result;
}

// // Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
// void create_tree_advance(const char* forward_file){
//     //fprintf(stderr,"TODO: %s\n",__func__);
//     root = create_node();
//     FILE* fp = fopen(forward_file, "r");
//     if (!fp) return;

//     char ip_str[32];
//     int mask_len, port;

//     while (fscanf(fp, "%s %d %d", ip_str, &mask_len, &port) == 3) {
//         uint32_t ip = ip_str_to_uint(ip_str);
//         struct TrieNode* node = root;
//         for (int i = 31; i >= 32 - mask_len; --i) {
//             int bit = (ip >> i) & 1;
//             if (!node->child[bit]) node->child[bit] = create_node();
//             node = node->child[bit];
//         }
//         node->port = port;
//     }
//     fclose(fp);
// }

// // Look up the ports of ip in file `lookup_file` using the advanced tree
// uint32_t *lookup_tree_advance(uint32_t* ip_vec){
//     //fprintf(stderr,"TODO: %s\n",__func__);
//     uint32_t* result = (uint32_t*)malloc(sizeof(uint32_t) * TEST_SIZE);
//     for (int i = 0; i < TEST_SIZE; ++i) {
//         uint32_t ip = ip_vec[i];
//         struct TrieNode* node = root;
//         int best = -1;
//         for (int j = 31; j >= 0 && node; --j) {
//             if (node->port != -1) best = node->port;
//             int bit = (ip >> j) & 1;
//             node = node->child[bit];
//         }
//         result[i] = best;
//     }
//     return result;
// 	//return NULL;
// }