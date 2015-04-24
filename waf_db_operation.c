#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <my_global.h>
#include <mysql.h>

static const int QUERY_BUFFER_SIZE=1024;
static const char *PROFILE_PATH="/home/pw/NS/pwd_waf/WAF_Profile";

//double WRITE_BUFFER_SIZE if char length reaches 1/2 capacity
static int WRITE_BUFFER_SIZE=1024;

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

insert_record_len(char *uri, char *parameter, int len);

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
		 printf("%s,%s\n", row[0],row[1]);
		 buf=(char *)malloc(255);
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
		 printf("%s;%s;%s;%s;%s;%s\n", row[0],row[1],row[2],row[3],row[4],row[5]);
		 buf=(char *)malloc(255);
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
	snprintf(q,sizeof(q),"SELECT IFNULL(FORMAT(STD(Len),2),-1) FROM Records WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return double_type_result(query);
}
	
int count_record(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT COUNT(*) FROM Records WHERE URI='%s' AND Parameter='%s'",uri,parameter);
	query=q;
	return int_type_result(query);
}
		
char* select_parameters_character_set(char *uri, char *parameter){
	char q[QUERY_BUFFER_SIZE];
	snprintf(q,sizeof(q),"SELECT COALESCE(Character_Set,\"NULL\") FROM Parameters WHERE URI='%s' AND Parameter='%s'",uri,parameter);
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

	

int queryTest(){	
	connect_mysql();  
	char *uri="login.php";
	char *para="p1";
	char *characterset="abc123!@#";
	int val=5;
	printf("Result: %d\n",select_max_parameter_num(uri));
	val=125;
	update_max_parameter_num(uri,125);
	update_max_parameter_num(uri,11554525);
	printf("Result: %d\n",select_max_parameter_num(uri));
	printf("Result: %d\n",select_max_parameter_num(uri));
	printf("%f\n",select_parameters_avg(uri,para));
	int avg=compute_len_avg(uri,para);
	int std=compute_len_std(uri,para);
	int count=count_record(uri,para);
	insert_parameters(uri,para,avg,std,count,"QWERTYU");
	update_parameters_stat(uri,para,2.33,0.22,7);
	printf("%f\n",select_parameters_avg(uri,para));
	printf("%f\n",select_parameters_avg(uri,para));
	printf("%d\n",select_parameters_count(uri,para));
	printf("%s\n",select_parameters_character_set(uri,para));
	insert_max_parameter_num("first_page.php",6);
	update_max_parameter_num("second_page.php",12345);

	int i;
	
	for (i=0;i<100;i++){
		char *buf=(char *)malloc(64);
		char *para2=malloc(255);
		buf[0]='\0';
		para2[0]='\0';
		strcat(para2,"para");
		sprintf(buf, "%d", i);
		strcat(para2,buf);
		//insert_parameters("second_page.php", para2, i*i,i,32,"NULL");
		insert_record_len("second_page.php","para2",i);
		free(buf);
		free(para2);
		}
	
	 avg=compute_len_avg("first_page.php",para);
	 std=compute_len_std("first_page.php",para);
	 count=count_record("first_page.php",para);
	insert_parameters("first_page.php",para,avg,std,count, characterset);
	
	avg=compute_len_avg("second_page.php","para2");
	 std=compute_len_std("second_page.php","para2");
	 count=count_record("second_page.php","para2");
	insert_parameters("second_page.php", "para2",avg,std,count, characterset);
	
	printf("%f\n",select_parameters_avg("first_page.php",para));
	printf("%d\n",select_parameters_count("first_page.php",para));
	printf("%f\n",select_parameters_sd("first_page.php",para));
	printf("%s\n",select_parameters_character_set("first_page.php",para));
	
	printf("AVG %f\n",compute_len_avg("second_page.php","para"));
	printf("STD %f\n",compute_len_std("second_page.php","para"));
	printf("Max Para Num of All: %d\n",select_max_parameter_num_all());
	write_profile();
	mysql_close(conn);	
	return 0;
}
