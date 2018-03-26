#include "server.h"
#include "myutils.h"
#include <string.h>
#include <arpa/inet.h>

client* genericGetClient(client* c){
	listNode *ln;
	listIter li;

	if(c->enable_client != true || c->is_control != true || c->argv[1]->type != OBJ_STRING){
		addReply(c, shared.err);
		return NULL;
	}

	client* cl = NULL;
	listRewind(server.clients, &li);
	while((ln = listNext(&li))){
		cl = listNodeValue(ln);
		if(!cl->hashid){
			cl = NULL;
			continue;
		}
		if(!strcasecmp(c->argv[1]->ptr, cl->hashid)){
			break;
		}
		cl = NULL;
	}
	return cl;
}


void enableCommand(client *c){
	if(c->argc == 3 && !strncmp(c->argv[1]->ptr, "1", 1)){
		c->hashid = sdsnew(c->argv[2]->ptr);
		c->enable_client = true;
		c->is_control = false;
		addReply(c, shared.ok);
	}
	else if(c->argc == 3 && !strncmp(c->argv[1]->ptr, "2", 1) && (!server.secretphrase || !strncmp(c->argv[2]->ptr, server.secretphrase, sdslen(server.secretphrase)))){
		c->enable_client = true;
		c->is_control = true;
		addReply(c, shared.ok);
	}
	else
		addReply(c, shared.err);
}

void getClientsCommand(client *c){
	listNode* ln;
	listIter li;
	char buf[1024];
	sds replySds = sdsempty();
	listRewind(server.clients, &li);
	bool hasClient = false;
	while((ln = listNext(&li))){
		client* cl = listNodeValue(ln);
		if(!cl->enable_client || cl->is_control || cl == c){
			continue;
		}
		hasClient = true;
		memset(buf, 0, sizeof(buf));
		sprintf(buf, "[%d] client->ip ", cl->fd);

		struct sockaddr_in sa;
		socklen_t len = sizeof(sa);
		if(!getpeername(cl->fd, (struct sockaddr*)&sa, &len)){
			strcat(buf + strlen(buf), inet_ntoa(sa.sin_addr));
			strcat(buf + strlen(buf), ": ");
			sprintf(buf + strlen(buf), "%d\t", sa.sin_port);
			replySds = sdscat(replySds, sdsnew(buf));
			/*sdscat(replySds, sdsnew(inet_ntoa(sa.sin_addr)));
			sdscat(replySds, sdsnew(": "));
			sdscat(replySds, sdsfromlonglong((long long)ntohs(sa.sin_port)));
			*/
		}
		
	}
	if(!hasClient){
		addReply(c, shared.err);
		return;
	}
	addReplySds(c, sdsnew("+"));
	addReplySds(c, replySds);
	addReplySds(c, sdsnew("\r\n"));
}



void sendCmdCommand(client *c){	
	client *cl = genericGetClient(c);

	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}
	addReply(cl, shared.mbulkhdr[c->argc - 2]);
	for(int i = 2; i < c->argc; i++){
		addReplyBulkCString(cl, c->argv[i]->ptr);
	}

	addReply(c, shared.ok);
}


void delFileCommand(client *c){
	client *cl = genericGetClient(c);
	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}

	addReply(cl, shared.mbulkhdr[2]);
	addReplyBulkCString(cl, "del");
	addReplyBulkCString(cl, c->argv[2]->ptr);

	addReply(c, shared.ok);

}

void printchar(unsigned char c){
		switch(c){
		case 0:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 9:
			printf("%c", c + '0');break;
		case 10:
			printf("a");break;
		case 11:
			printf("b");break;
		case 12:
			printf("c");break;
		case 13:
			printf("d");break;
		case 14:
			printf("e");break;
		case 15:
			printf("f");break;
		}
		
}

void printhex(unsigned char buf[], int size){
	for(int i = 0; i < size; i++){
		printchar(buf[i] >> 4);
		printchar(buf[i] & 0x0f);

	}
	printf("\n");
}

void lockFileCommand(client *c){
	unsigned char hash[20];
	client *cl = genericGetClient(c);
	if(cl == NULL){
		addReply(c, shared.err);
		return;
	}
	gethashforaes(sdsnew(c->argv[1]->ptr), hash);
	memset(hash + 16, 0 , 4);
	printhex(hash, 20);

	addReply(cl, shared.mbulkhdr[3]);
	addReplyBulkCString(cl, "lock");
	addReplyBulkCString(cl, hash);
	addReplyBulkCString(cl, c->argv[2]->ptr);

	addReply(c, shared.ok);
}
