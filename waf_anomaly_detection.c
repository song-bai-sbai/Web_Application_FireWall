// This is for Train Mode code
#include "httpd.h"
#include <string.h>

typedef struct{
	const char * key;
	const char * val;
	int length;
}Params;

Params * getGetParams(request_rec *r, apr_off_t * len);
Params * getPostParms(request_rec *r, apr_off_t * postSize);
void saveRequestInfo();
void generateProfile();

void saveRequestInfo(request_rec *r){
	int currentMaxParamsNum = 0;
	apr_off_t getSize = 0;
	apr_off_t postSize = 0;
	Params * getParams = getGetParams(r, &getSize);
	Params * postParams = getPostParms(r, &postSize);
	char * uri = r->uri;
	
	// Update max parameters number for a page
	currentMaxParamsNum = getSize + postSize;
	int maxInDB = 0;//TODO
	if(maxInDB == -1){
		// insert to DB
	}else{
		if(currentMaxParamsNum > maxInDB){
			// update DB value
		}
	}
	
	// Save the record into DB
	int i = 0;
	for(i = 0; i< getSize; i++){
		// save get paramether info into DB
		
		// Update characters for this parameter
	}
	
	for(i = 0; i< postSize; i++){
		// save post paramether info into DB
		
		// Update characters for this parameter
	}
}

void generateProfile(){

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
		ap_rprintf(r,"key : val : len: is %s : %s : %d ===", params[i].key, params[i].val, params[i].length);
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
        ap_rprintf(r,"key : val : len: is %s : %s : %d ===", params[i].key, params[i].val, params[i].length);
        i++;
    }
    *postSize = i;

    return params;
}

void examineGetParams(request_rec *r, Params * getParams){

}
