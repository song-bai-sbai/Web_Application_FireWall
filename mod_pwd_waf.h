typedef struct {
    const char *key;
    const char *value;
} KVPair;

typedef struct{
   char key[2];
   char value[2];
}Signiture;

static int LEGAL = 1001;

static int ILLEGAL = 1002;

KVPair *readPostParms(request_rec *r);

int checkGETParms(request_rec *r, Signiture * getSigList, int listSize);

int checkPOSTParms(request_rec *r, Signiture * postSigList, int listSize);

int checkHEADERParms(request_rec *r, Signiture * headerSigList, int listSize);

int isLegal(const char* key, const char* value, Signiture * list, int listSize);

