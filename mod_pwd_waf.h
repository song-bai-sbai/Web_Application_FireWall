#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_request.h"

#include "ap_config.h"
#include "apr_strings.h"
#include "apr_network_io.h"
#include <apr_file_info.h>
#include <apr_file_io.h>
#include <apr_tables.h>
#include <util_script.h>
#include <ctype.h>

#include "readSigConfig.c"
#include "waf_anomaly_detection.c"

typedef struct {
    const char *key;
    const char *value;
} KVPair;

static char* changeModeURI ="/modeChange";
static const char *ADMIN_CONFIG="/home/pw/NS/pwd_waf/WAF_Admin";
static const char *MODE_CONFIG_PATH="/home/pw/NS/pwd_waf/WAF_Mode";

static int LEGAL = 1001;

static int ILLEGAL = 1002;

static char * illegalStr;

static int TRAINMODE = 2001;

static int DETECTIONMODE = 2002;

static int GENERATEPROFILE = 2003;

static int MODE = 2002;

KVPair *readPostParms(request_rec *r);

int checkGETParms(request_rec *r, Signiture * getSigList, int listSize);

int checkPOSTParms(request_rec *r, Signiture * postSigList, int listSize);

int checkHEADERParms(request_rec *r, Signiture * headerSigList, int listSize);

int isLegal(request_rec *r, const char* key, const char* value, Signiture * list, int listSize);

void showIllegalStr();

int isChangeMode(const char* uri);

int isAdmin(request_rec *r);

void read_admin_file(char *user, char *password);

void showModeChangeInfo(request_rec *r, int mode);

void showDetectionResult(request_rec *r, char * result);

int readCurrentMode();

void writeCurrentMode(int mode);

void toLowerCase(char * str);
