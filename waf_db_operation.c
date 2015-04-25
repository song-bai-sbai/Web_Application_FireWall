#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <my_global.h>
#include <mysql.h>

typedef struct{
	 char *uri;
	 char *para;
} UPPair; 

static const char *PROFILE_PATH="/home/pw/NS/pwd_waf/WAF_Profile";

//double WRITE_BUFFER_SIZE if char length reaches 1/2 capacity
static int WRITE_BUFFER_SIZE=1024;
static const int QUERY_BUFFER_SIZE=1024;
static int VARCHAR_SIZE=255;

static UPPair *uriParaList;
static MYSQL *conn;
static char *server = "localhost"; 
static char *user = "root"; 
static char *password = "123";
static char *database = "waf_db";
static char *query;
static char *profile;

int int_type_result(char *query);
double double_type_result(char *query);

void connect_mysql();
int execute_query(char *query);
int select_max_parameter_num_all();
int select_max_parameter_num(char *uri);
int insert_max_parameter_num(char *uri, int val);
int update_max_parameter_num(char *uri, int val);

double select_parameters_avg(char *uri, char *parameter);
double select_parameters_sd(char *uri, char *parameter);
int select_parameters_count(char *uri, char *parameter);
char* select_parameters_character_set(char *uri, char *parameter);
double compute_len_avg(char *uri, char *parameter);
double compute_len_std(char *uri, char *parameter);
int count_record(char *uri, char *parameter);

int insert_parameters(char *uri, char *parameter, double avg, double sd, int count, char *str);
int update_parameters_stat(char *uri, char *parameter, double avg, double sd, int count);
int update_parameters_character_set(char *uri, char *parameter, char *str);

int insert_record_len(char *uri, char *parameter, int len);

void updateParametersTable();

void expand_write_buffer();

void expand_write_buffer(){
	int length = strlen(profile);
	if (length>WRITE_BUFFER_SIZE/2){
		WRITE_BUFFER_SIZE=WRITE_BUFFER_SIZE*2;
		profile = (char *)realloc(profile, WRITE_BUFFER_SIZE);
		printf("%s, %d, %s, %d \n","WRITE_BUFFER_SIZE Expanded ",WRITE_BUFFER_SIZE," profile length ",length);
	}
}

void write_profile(){
	FILE *f = fopen(PROFILE_PATH, "w");
	if (f == NULL){
		exit(1);
	}
	profile=(char *)malloc(WRITE_BUFFER_SIZE);
	profile[0] = '\0'; 
	strcat(profile, "Maximum number of parameters seen for all requests across all pages:\n");

	char *buf=(char *)malloc(64);
	sprintf(buf, "%d;\n", select_max_parameter_num_all());
	strcat(profile,buf);
	
	strcat(profile,"Maximum number of parameters seen for every specific page:\n");
	expand_write_buffer();
	query="SELECT * FROM Pages";
	execute_query(query);
	MYSQL_RES *res = mysql_use_result(conn);
	if (res!=NULL){
	MYSQL_ROW row;
		while ((row = mysql_fetch_row(res))!=NULL){
			buf=(char *)malloc(VARCHAR_SIZE*2);
			sprintf(buf,"%s;%s\n", row[0],row[1]); 
			strcat(profile,buf);
			expand_write_buffer();
		}
	}
	
	strcat(profile,"Average length of values and Character set for every specific parameter of every specific page:\n");
	expand_write_buffer();
	query="SELECT * FROM Parameters";
	execute_query(query);
	res = mysql_use_result(conn);
	if (res!=NULL){
	MYSQL_ROW row;
		while ((row = mysql_fetch_row(res))!=NULL){
			buf=(char *)malloc(VARCHAR_SIZE*6);
			sprintf(buf,"%s;%s;%s;%s;%s;%s\n", row[0],row[1],row[2],row[3],row[4],row[5]); 
			strcat(profile,buf);
			expand_write_buffer();
		}
	}
	
	free(buf);
	mysql_free_result(res);
		
	fprintf(f, "%s\n", profile);
	fclose(f);
}

void connect_mysql(){
   conn = mysql_init(NULL);
   if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
      fprintf(stderr, "%s\n", mysql_error(conn));
      exit(1);
      }
}

/*
 * return 0 if no error,
 * else return error code
 * */
int execute_query(char *query){
	printf("Query: %s \n", query);
	if (mysql_query(conn, query)) {
		fprintf(stderr, "%s\n", mysql_error(conn));
		return mysql_errno(conn);
      }
    return 0;
}

/*
 * if return type of query result is double, call double_type_reuslt(char *query);
 * */
double double_type_result(char *query){
	if(!execute_query(query)){
		MYSQL_RES *res = mysql_use_result(conn);
		MYSQL_ROW row= mysql_fetch_row(res);
		if (row){
			char str[QUERY_BUFFER_SIZE];
			strcpy(str, row[0]);
			mysql_free_result(res);
			return atof(str);
		}
		mysql_free_result(res);
	}	
	return (double)(-1);
}

int int_type_result(char *query){
	if(!execute_query(query)){
		MYSQL_RES *res = mysql_use_result(conn);
		MYSQL_ROW row= mysql_fetch_row(res);
		if (row){
			char str[QUERY_BUFFER_SIZE];
			strcpy(str, row[0]);
			mysql_free_result(res);	
			return atoi(str);
		}
		mysql_free_result(res);
	}
	return -1;
}
	
int select_max_parameter_num_all(){
	query="SELECT COALESCE(MAX(Max_Parameter_Num),-1) FROM Pages";
	return int_type_result(query);
}

int select_max_parameter_num(char *uri){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT IFNULL(Max_Parameter_Num,-1) FROM Pages WHERE URI='%s'",uri);
	query=q;
	return int_type_result(query);
}

int insert_max_parameter_num(char *uri, int val){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"INSERT INTO Pages VALUES('%s',%d) ON DUPLICATE KEY UPDATE URI=URI",uri,val);
	query=q;
	return execute_query(query);
}
	
int update_max_parameter_num(char *uri, int val){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"UPDATE Pages SET Max_Parameter_Num=%d WHERE URI='%s'" ,val,uri);
	query=q;
	return execute_query(query);
}

double select_parameters_avg(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT IFNULL(Avg,-1.0) FROM Parameters WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return double_type_result(query);
}

double select_parameters_sd(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT IFNULL(SD,-1.0) FROM Parameters WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return double_type_result(query);
}

int select_parameters_count(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT IFNULL(Count,-1) FROM Parameters WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return int_type_result(query);
}

double compute_len_avg(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT IFNULL(AVG(Len),-1) FROM Records WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return double_type_result(query);
}

double compute_len_std(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT IFNULL(STD(Len),-1) FROM Records WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return double_type_result(query);
}
	
void updateParametersTable(){
	query="SELECT COUNT(*) FROM Parameters";
	int total=int_type_result(query);
	if (total>0){
		uriParaList=(UPPair *) malloc(sizeof(UPPair)*total);
		query="SELECT * FROM Parameters";
		execute_query(query);
		MYSQL_RES *res = mysql_use_result(conn);
		MYSQL_ROW row;
		int num=0;
		char *uriBuf;
		char *paraBuf;
		while ((row = mysql_fetch_row(res))!=NULL){
			uriBuf=(char *)malloc(VARCHAR_SIZE); 
			paraBuf=(char *)malloc(VARCHAR_SIZE);
			strncpy(uriBuf,row[0],VARCHAR_SIZE);
			strncpy(paraBuf,row[1],VARCHAR_SIZE); 
			uriParaList[num].uri=uriBuf;
			uriParaList[num].para=paraBuf;
			num++;
		}
		mysql_free_result(res);
		int i;
		for (i=0;i<total;i++){
			update_parameters_stat(uriParaList[i].uri,uriParaList[i].para,compute_len_avg(uriParaList[i].uri,uriParaList[i].para),compute_len_std(uriParaList[i].uri,uriParaList[i].para),count_record(uriParaList[i].uri,uriParaList[i].para));
		}
		if(uriBuf) free(uriBuf);
		if(paraBuf) free(paraBuf);
	}	
}

int count_record(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT COUNT(*) FROM Records WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return int_type_result(query);
}

char* select_parameters_character_set(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT COALESCE(Character_Set,\"\") FROM Parameters WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	if(!execute_query(query)){
		MYSQL_RES *res = mysql_use_result(conn);
		MYSQL_ROW row= mysql_fetch_row(res);
		if (row){
			char str[QUERY_BUFFER_SIZE];
			strcpy(str, row[0]);
			char *p=&str[0];
			mysql_free_result(res);
			return p;
		}
		mysql_free_result(res);
	}
	return NULL;
}

int insert_parameters(char *uri, char *parameter, double avg, double sd, int count, char *characterset){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"INSERT INTO Parameters VALUES('%s','%s',%f, %f ,%d,'%s') ON DUPLICATE KEY UPDATE URI=URI",uri,parameter,avg,sd, count,characterset);
	query=q;
	return execute_query(query);
}

int update_parameters_stat(char *uri, char *parameter, double avg, double sd, int count){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"UPDATE Parameters SET Avg=%f, SD=%f, Count=%d WHERE URI='%s' AND Parameter='%s'",avg,sd,count,uri,parameter);
	query=q;
	return execute_query(query);
}

int update_parameters_character_set(char *uri, char *parameter, char *characterset){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"UPDATE Parameters SET Character_Set='%s' WHERE URI='%s' AND Parameter='%s'",characterset,uri,parameter);
	query=q;
	return execute_query(query);
}

int insert_record_len(char *uri, char *parameter, int len){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"INSERT INTO Records(URI,Parameter,Len) VALUES('%s', '%s', %d)",uri,parameter,len);
	query=q;
	return execute_query(query);
}





