#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
	const char *key;
	const char *value;
} Signiture;

static int SIGNITURE_BUFFER_SIZE=256;
static char *SIGNITURE_CONFIG="/home/pw/NS/pwd_waf/WAF_Sig_Conf";

static 	Signiture *headerList, *getList, *postList;
static int headerNum=0,getNum=0,postNum=0;

void parse_signiture(char *signiture ){
	char *delim="/*";
	char *i=strstr(signiture,delim);
	if (i!=NULL) {
		*i='\0';
	}

	delim=",CONTAINS:";
	i=strstr(signiture,delim);
	if (i==NULL) {
		printf("%s","delim not found");
		return;
	}
	char *buf=(char *)malloc(SIGNITURE_BUFFER_SIZE); 
	int length = strlen(delim);
	strncpy(buf, signiture, (i - signiture));

	char *left=buf;
	char *tempRight=(i+length+1);
	i=strstr(tempRight,"\"");
	char *right=(char *)malloc(SIGNITURE_BUFFER_SIZE); 
	strncpy(right, tempRight, (i-tempRight));

	if (strstr(left,"HEADER:") != NULL){
		i=strstr(left,"HEADER:");
		length=strlen("HEADER:");
		headerList[headerNum].key=i+length;
		headerList[headerNum].value=right;
		headerNum++;
	}

	else if (strstr(left,"REQUEST_METHOD:GET,PARAMETER:") != NULL){
		i=strstr(left,"REQUEST_METHOD:GET,PARAMETER:");
		length=strlen("REQUEST_METHOD:GET,PARAMETER:");
		getList[getNum].key=i+length;
		getList[getNum].value=right;
		getNum++;
	}
	else if (strstr(left,"REQUEST_METHOD:POST,PARAMETER:") != NULL){
		i=strstr(left,"REQUEST_METHOD:POST,PARAMETER:");
		length=strlen("REQUEST_METHOD:POST,PARAMETER:");
		postList[postNum].key=i+length;
		postList[postNum].value=right;
		postNum++;
	}

}

void parseConfigFile(){
	FILE * fp;
	fp = fopen(SIGNITURE_CONFIG, "r");
	int headerCount=0,getCount=0,postCount=0;
	char *line = (char *)malloc(SIGNITURE_BUFFER_SIZE);
	if(fp) {
		while (1) {
			if (fgets(line,SIGNITURE_BUFFER_SIZE, fp) == NULL){ 
				break;}
			if(strstr(line, "HEADER:")!=NULL){
				headerCount++;
			}else if(strstr(line, "REQUEST_METHOD:GET,PARAMETER:")!=NULL){
				getCount++;
			}else if(strstr(line, "REQUEST_METHOD:POST,PARAMETER:")!=NULL){
				postCount++;
			}
		}
	fclose(fp);           
	}
	fp = fopen(SIGNITURE_CONFIG, "r");
	headerList = (Signiture *) malloc(sizeof(Signiture)*(headerCount));
	getList = (Signiture *) malloc(sizeof(Signiture)*(getCount));
	postList = (Signiture *) malloc(sizeof(Signiture)*(postCount));	

	line = (char *)malloc(SIGNITURE_BUFFER_SIZE);	
	if(fp) {
		while (1) {
			if (fgets(line,SIGNITURE_BUFFER_SIZE, fp) == NULL){
				break;}
			parse_signiture(line);
		} 
	fclose(fp);           
	}

	if (line){
		free(line);
	}
}



