#include "mospf_database.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

struct list_head mospf_db;

void init_mospf_db()
{
	init_list_head(&mospf_db);
}

void print_lsdb(){
	printf("LSDB:\n");
	printf("--------------------------------------\n");
	mospf_db_entry_t* lsas;
	list_for_each_entry(lsas, &mospf_db, list){
		for (int i = 0; i < lsas->nadv; ++i){
			printf("%x\t%x\t%x\t%x\t%d\n", lsas->rid, lsas->array[i].network, lsas->array[i].mask, lsas->array[i].rid, lsas->seq);
		}
		printf("--------------------------------------\n");
	}
}
