// This is for Train Mode code
#include "httpd.h"
#include <string.h>
#include "waf_db_operation.c"

typedef struct{
	const char * key;
	const char * val;
	int length;
}Params;

static int EXCEEDMAXPARAMNUM = 4001;

static int PARAMLENILLEGAL = 4002;

static int CONTAINSNOSEENCHAR = 4003;

static int PASSDETECTION = 4004;

static int UNKNOWNPRARM = 4005;

static int EXCEEDALLMAXNUM = 4006;

Params * getGetParams(request_rec *r, apr_off_t * len);

Params * getPostParms(request_rec *r, apr_off_t * postSize);

void saveRequestInfo(request_rec *r);

void generateProfile();

int detectRequest(request_rec * r);

int isParamsLenLegal(const char * uri, const char* param, int len);

int allCharSeen(const char * uri, const char* param,const char * val);

int isAllCharLegal(const char * cur, const char * seenChar);

void updateCharSet(const char * cur, char * charSet);

int isEmpty(const char * str);

int isKnownParams(const char * uri, const char* param);

// In trainning mode, to save all request info
void saveRequestInfo(request_rec *r){
	int currentMaxParamsNum = 0;
	apr_off_t getSize = 0;
	apr_off_t postSize = 0;
	Params * getParams = getGetParams(r, &getSize);
	Params * postParams = getPostParms(r, &postSize);
	char * uri = r->uri;
	
	// Update max parameters number for a page
	currentMaxParamsNum = getSize + postSize;
	int maxInDB = select_max_parameter_num(uri);
	if(maxInDB == -1){
		// insert to DB
		insert_max_parameter_num(uri, currentMaxParamsNum);
	}else{
		if(currentMaxParamsNum > maxInDB){
			// update DB value
			update_max_parameter_num(uri, currentMaxParamsNum);
		}
	}
	
	// Save the record into DB
	int i = 0;
	for(i = 0; i< getSize; i++){
		// save get paramether info into DB
		insert_record_len(uri, getParams[i].key, getParams[i].length);
		
		// Update characters set for this parameter
		char * charSet = select_parameters_character_set(uri, getParams[i].key);
		if(charSet == NULL){
			// This is the first time to see this parameter
			insert_parameters(uri, getParams[i].key, 0, 0, 1, getParams[i].val);
		}else{
			// Update char set
			updateCharSet(getParams[i].val, charSet);
			//ap_rprintf(r,"new char set is %s--\n", charSet);
			update_parameters_character_set(uri, getParams[i].key, charSet);
		}
	}
	
	for(i = 0; i< postSize; i++){
		// save post paramether info into DB
		insert_record_len(uri, postParams[i].key, postParams[i].length);
		// Update characters set for this parameter
		char * charSet = select_parameters_character_set(uri, postParams[i].key);
		if(charSet == NULL){
			// This is the first time to see this parameter
			insert_parameters(uri, postParams[i].key, 0, 0, 1, postParams[i].val);
		}else{
			// Update char set
			updateCharSet(postParams[i].val, charSet);
			update_parameters_character_set(uri, postParams[i].key, charSet);
		}
	}
}

// After finish trainning, generate a profile 
void generateProfile(){
	updateParametersTable();
	write_profile();
}

Params * getGetParams(request_rec *r, apr_off_t * getSize){
	Params * params;
	apr_table_t *GET;	
	ap_args_to_table(r, &GET);
	
	const apr_array_header_t *parmsArray = apr_table_elts(GET);
	const apr_table_entry_t * getParms = (apr_table_entry_t*)parmsArray->elts;
	
	*getSize = parmsArray->nelts;
	
	params = apr_pcalloc(r->pool, sizeof(Params) * (*getSize + 1));
	int i = 0;
	for (i = 0; i < *getSize; i++) {
		params[i].key = getParms[i].key;
		params[i].val = getParms[i].val;
		params[i].length = strlen(params[i].val);
		//ap_rprintf(r,"key : val : len: is %s : %s : %d ===", params[i].key, params[i].val, params[i].length);
	}
	return params;
}

Params *getPostParms(request_rec *r, apr_off_t * postSize) {
    apr_array_header_t *pairs = NULL;
    apr_off_t len;
    apr_size_t size;
    int res;
    int i = 0;
    char *buffer;
    Params *params = NULL;
    
    res = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);
    if (res != OK || !pairs) return NULL; 
    params = apr_pcalloc(r->pool, sizeof(Params) * (pairs->nelts + 1));
    while (pairs && !apr_is_empty_array(pairs)) {
        ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
        apr_brigade_length(pair->value, 1, &len);
        size = (apr_size_t) len;
        buffer = apr_palloc(r->pool, size + 1);
        apr_brigade_flatten(pair->value, buffer, &size);
        buffer[len] = 0;
        params[i].key = apr_pstrdup(r->pool, pair->name);
        params[i].val = buffer;
        params[i].length = strlen(buffer);
        //ap_rprintf(r,"key : val : len: is %s : %s : %d ===", params[i].key, params[i].val, params[i].length);
        i++;
    }
    *postSize = i;

    return params;
}

// In detection mode, do anomaly detection
int detectRequest(request_rec * r){
	int currentMaxParamsNum = 0;
	apr_off_t getSize = 0;
	apr_off_t postSize = 0;
	Params * getParams = getGetParams(r, &getSize);
	Params * postParams = getPostParms(r, &postSize);
	char * uri = r->uri;
	
	// Update max parameters number for a page
	currentMaxParamsNum = getSize + postSize;
	int maxInDB = select_max_parameter_num(uri);
	if(maxInDB == -1){
		// The request is not store in DB, compare it with all pages max
		maxInDB = select_max_parameter_num_all();
		if(maxInDB < currentMaxParamsNum){
			// exceed max parameter number
			return EXCEEDALLMAXNUM;
		}else{
			return PASSDETECTION;
		}
	}
	if(maxInDB < currentMaxParamsNum){
		// exceed max parameter number
		return EXCEEDMAXPARAMNUM;
	}
	
	int i = 0;
	for(i = 0; i< getSize; i++){
		if(!isKnownParams(uri, getParams[i].key)){
			// The parameter is unknow
			ap_rprintf(r,"<H3>Parameter:'%s' is unknown!</H3>",getParams[i].key);
			return UNKNOWNPRARM;
		}
		if(!isParamsLenLegal(uri, getParams[i].key, getParams[i].length)){
			// parameters length is illegal
			ap_rprintf(r,"<H3>Parameter:'%s' length is illegal!</H3>",getParams[i].key);
			return PARAMLENILLEGAL;
		}
		
		if(!allCharSeen(uri, getParams[i].key,getParams[i].val)){
			// Contains no seen characters
			ap_rprintf(r,"<H3>Parameter:'%s' contains illegal characters!</H3>",getParams[i].key);
			return CONTAINSNOSEENCHAR;
		}
	}
	
	for(i = 0; i< postSize; i++){
		if(!isKnownParams(uri, postParams[i].key)){
			// The parameter is unknow
			ap_rprintf(r,"<H3>Parameter:'%s' is unknown!</H3>",postParams[i].key);
			return UNKNOWNPRARM;
		}
		if(!isParamsLenLegal(uri, postParams[i].key, postParams[i].length)){
			// parameters length is illegal
			ap_rprintf(r,"<H3>Parameter:'%s' length is illegal!</H3>",postParams[i].key);
			return PARAMLENILLEGAL;
		}
		
		if(!allCharSeen(uri, postParams[i].key,postParams[i].val)){
			// Contains no seen characters
			ap_rprintf(r,"<H3>Parameter:'%s' contains illegal characters!</H3>",postParams[i].key);
			return CONTAINSNOSEENCHAR;
		}
	}
	
	return PASSDETECTION;
}

// Get mean and standard deviation, and calculate mean +- 3d
// Then compare
// Return 1 if it is LEGAL, and Return 0 if it is ILLEGAL
int isParamsLenLegal(const char * uri, const char* param, int len){
	double mean = select_parameters_avg(uri, param);
	double d = select_parameters_sd(uri, param);
	if(len <= (mean + 3*d) && len >=(mean - 3*d)){
		return 1;
	}
	return 0;
}

// check whether the parameters contains char that not seen
int allCharSeen(const char * uri, const char* param,const char * val){
	char * charSet = select_parameters_character_set(uri, param);
	if(!isAllCharLegal(val, charSet)){
		return 0;
	}
	return 1;
}

int isAllCharLegal(const char * cur, const char * seenChar){
    int len = strlen(cur);
    int i = 0;
    for (i=0; i<len; i++) {
        if (strchr(seenChar,cur[i])==NULL) {
            return 0;
        }
    }
    return 1;
}

void updateCharSet(const char * cur, char * charSet){
    int len = strlen(cur);
    int i = 0;
    int size = 0;
    for(i=0; i<len; i++){
        if (strchr(charSet, cur[i]) == NULL) {
            size = strlen(charSet);
            charSet[size]=cur[i];
            charSet[size+1]='\0';
        }
    }
}

int isEmpty(const char * str){
	if(strcmp(str,"")==0){
		return 1;
	}
	return 0;
}

int isKnownParams(const char * uri, const char* param){
	int count = select_parameters_count(uri, param);
	if(count < 0){
		return 0;
	}
	return 1;
}
