/**
 * \file lora_detector_change_distance.c
 * \brief LoRaWAN Detector of NEMEA module.
 * \author Erik Gresak <erik.gresak@vsb.cz>
 * \date 2018
 */
/*
 * Copyright (C) 2018 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

/**
 * Implement Semtech
 * Description: Configure LoRa concentrator and record received packets in a log file
 * License: Revised BSD License, see LICENSE.TXT file include in the project
 * Maintainer: Sylvain Miermont
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <stddef.h> 
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include "lora_packet.h"
#include <string.h>
#include "device_list.h"

#include "parson.h"
#include "libloragw/inc/loragw_hal.h"

/** Maximum message size */
#define MAX_MSG_SIZE 10000

/** Private Macros */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MSG(args...) fprintf(stderr,"cesnet_pkt_analyzer: " args)

/* signal handling variables */
struct sigaction sigact; /* SIGQUIT&SIGINT&SIGTERM signal handling */
static int exit_sig = 0; /* 1 -> application terminates cleanly (shut down hardware, close open files, etc) */
static int quit_sig = 0; /* 1 -> application terminates without shutting down the hardware */

/* configuration variables needed by the application  */
uint64_t lgwm = 0; /* LoRa gateway MAC address */
char lgwm_str[17];

/* clock and log file management */
time_t now_time;
time_t log_start_time;
FILE * log_file = NULL;
char log_file_name[64];

/** Private function declaration */
static void sig_handler(int sigio);
int parse_SX1301_configuration(const char * conf_file);
int parse_gateway_configuration(const char * conf_file);
void open_log(void);
void usage(void);

/** Private function definition */
static void sig_handler(int sigio) {
    if (sigio == SIGQUIT) {
        quit_sig = 1;
        ;
    } else if ((sigio == SIGINT) || (sigio == SIGTERM)) {
        exit_sig = 1;
    }
}

int parse_SX1301_configuration(const char * conf_file) {
    int i;
    const char conf_obj[] = "SX1301_conf";
    char param_name[32]; /* used to generate variable parameter names */
    const char *str; /* used to store string value from JSON object */
    struct lgw_conf_board_s boardconf;
    struct lgw_conf_rxrf_s rfconf;
    struct lgw_conf_rxif_s ifconf;
    JSON_Value *root_val;
    JSON_Object *root = NULL;
    JSON_Object *conf = NULL;
    JSON_Value *val;
    uint32_t sf, bw;

    /* try to parse JSON */
    root_val = json_parse_file_with_comments(conf_file);
    root = json_value_get_object(root_val);
    if (root == NULL) {
        MSG("ERROR: %s id not a valid JSON file\n", conf_file);
        exit(EXIT_FAILURE);
    }
    conf = json_object_get_object(root, conf_obj);
    if (conf == NULL) {
        MSG("INFO: %s does not contain a JSON object named %s\n", conf_file, conf_obj);
        return -1;
    } else {
        MSG("INFO: %s does contain a JSON object named %s, parsing SX1301 parameters\n", conf_file, conf_obj);
    }

    /* set board configuration */
    memset(&boardconf, 0, sizeof boardconf); /* initialize configuration structure */
    val = json_object_get_value(conf, "lorawan_public"); /* fetch value (if possible) */
    if (json_value_get_type(val) == JSONBoolean) {
        boardconf.lorawan_public = (bool) json_value_get_boolean(val);
    } else {
        MSG("WARNING: Data type for lorawan_public seems wrong, please check\n");
        boardconf.lorawan_public = false;
    }
    val = json_object_get_value(conf, "clksrc"); /* fetch value (if possible) */
    if (json_value_get_type(val) == JSONNumber) {
        boardconf.clksrc = (uint8_t) json_value_get_number(val);
    } else {
        MSG("WARNING: Data type for clksrc seems wrong, please check\n");
        boardconf.clksrc = 0;
    }
    MSG("INFO: lorawan_public %d, clksrc %d\n", boardconf.lorawan_public, boardconf.clksrc);
    /* all parameters parsed, submitting configuration to the HAL */
    if (lgw_board_setconf(boardconf) != LGW_HAL_SUCCESS) {
        MSG("WARNING: Failed to configure board\n");
    }

    /* set configuration for RF chains */
    for (i = 0; i < LGW_RF_CHAIN_NB; ++i) {
        memset(&rfconf, 0, sizeof (rfconf)); /* initialize configuration structure */
        sprintf(param_name, "radio_%i", i); /* compose parameter path inside JSON structure */
        val = json_object_get_value(conf, param_name); /* fetch value (if possible) */
        if (json_value_get_type(val) != JSONObject) {
            MSG("INFO: no configuration for radio %i\n", i);
            continue;
        }
        /* there is an object to configure that radio, let's parse it */
        sprintf(param_name, "radio_%i.enable", i);
        val = json_object_dotget_value(conf, param_name);
        if (json_value_get_type(val) == JSONBoolean) {
            rfconf.enable = (bool) json_value_get_boolean(val);
        } else {
            rfconf.enable = false;
        }
        if (rfconf.enable == false) { /* radio disabled, nothing else to parse */
            MSG("INFO: radio %i disabled\n", i);
        } else { /* radio enabled, will parse the other parameters */
            snprintf(param_name, sizeof param_name, "radio_%i.freq", i);
            rfconf.freq_hz = (uint32_t) json_object_dotget_number(conf, param_name);
            snprintf(param_name, sizeof param_name, "radio_%i.rssi_offset", i);
            rfconf.rssi_offset = (float) json_object_dotget_number(conf, param_name);
            snprintf(param_name, sizeof param_name, "radio_%i.type", i);
            str = json_object_dotget_string(conf, param_name);
            if (!strncmp(str, "SX1255", 6)) {
                rfconf.type = LGW_RADIO_TYPE_SX1255;
            } else if (!strncmp(str, "SX1257", 6)) {
                rfconf.type = LGW_RADIO_TYPE_SX1257;
            } else {
                MSG("WARNING: invalid radio type: %s (should be SX1255 or SX1257)\n", str);
            }
            snprintf(param_name, sizeof param_name, "radio_%i.tx_enable", i);
            val = json_object_dotget_value(conf, param_name);
            if (json_value_get_type(val) == JSONBoolean) {
                rfconf.tx_enable = (bool) json_value_get_boolean(val);
            } else {
                rfconf.tx_enable = false;
            }
            MSG("INFO: radio %i enabled (type %s), center frequency %u, RSSI offset %f, tx enabled %d\n", i, str, rfconf.freq_hz, rfconf.rssi_offset, rfconf.tx_enable);
        }
        /* all parameters parsed, submitting configuration to the HAL */
        if (lgw_rxrf_setconf(i, rfconf) != LGW_HAL_SUCCESS) {
            MSG("WARNING: invalid configuration for radio %i\n", i);
        }
    }

    /* set configuration for LoRa multi-SF channels (bandwidth cannot be set) */
    for (i = 0; i < LGW_MULTI_NB; ++i) {
        memset(&ifconf, 0, sizeof (ifconf)); /* initialize configuration structure */
        sprintf(param_name, "chan_multiSF_%i", i); /* compose parameter path inside JSON structure */
        val = json_object_get_value(conf, param_name); /* fetch value (if possible) */
        if (json_value_get_type(val) != JSONObject) {
            MSG("INFO: no configuration for LoRa multi-SF channel %i\n", i);
            continue;
        }
        /* there is an object to configure that LoRa multi-SF channel, let's parse it */
        sprintf(param_name, "chan_multiSF_%i.enable", i);
        val = json_object_dotget_value(conf, param_name);
        if (json_value_get_type(val) == JSONBoolean) {
            ifconf.enable = (bool) json_value_get_boolean(val);
        } else {
            ifconf.enable = false;
        }
        if (ifconf.enable == false) { /* LoRa multi-SF channel disabled, nothing else to parse */
            MSG("INFO: LoRa multi-SF channel %i disabled\n", i);
        } else { /* LoRa multi-SF channel enabled, will parse the other parameters */
            sprintf(param_name, "chan_multiSF_%i.radio", i);
            ifconf.rf_chain = (uint32_t) json_object_dotget_number(conf, param_name);
            sprintf(param_name, "chan_multiSF_%i.if", i);
            ifconf.freq_hz = (int32_t) json_object_dotget_number(conf, param_name);
            // TODO: handle individual SF enabling and disabling (spread_factor)
            MSG("INFO: LoRa multi-SF channel %i enabled, radio %i selected, IF %i Hz, 125 kHz bandwidth, SF 7 to 12\n", i, ifconf.rf_chain, ifconf.freq_hz);
        }
        /* all parameters parsed, submitting configuration to the HAL */
        if (lgw_rxif_setconf(i, ifconf) != LGW_HAL_SUCCESS) {
            MSG("WARNING: invalid configuration for LoRa multi-SF channel %i\n", i);
        }
    }

    /* set configuration for LoRa standard channel */
    memset(&ifconf, 0, sizeof (ifconf)); /* initialize configuration structure */
    val = json_object_get_value(conf, "chan_Lora_std"); /* fetch value (if possible) */
    if (json_value_get_type(val) != JSONObject) {
        MSG("INFO: no configuration for LoRa standard channel\n");
    } else {
        val = json_object_dotget_value(conf, "chan_Lora_std.enable");
        if (json_value_get_type(val) == JSONBoolean) {
            ifconf.enable = (bool) json_value_get_boolean(val);
        } else {
            ifconf.enable = false;
        }
        if (ifconf.enable == false) {
            MSG("INFO: LoRa standard channel %i disabled\n", i);
        } else {
            ifconf.rf_chain = (uint32_t) json_object_dotget_number(conf, "chan_Lora_std.radio");
            ifconf.freq_hz = (int32_t) json_object_dotget_number(conf, "chan_Lora_std.if");
            bw = (uint32_t) json_object_dotget_number(conf, "chan_Lora_std.bandwidth");
            switch (bw) {
                case 500000: ifconf.bandwidth = BW_500KHZ;
                    break;
                case 250000: ifconf.bandwidth = BW_250KHZ;
                    break;
                case 125000: ifconf.bandwidth = BW_125KHZ;
                    break;
                default: ifconf.bandwidth = BW_UNDEFINED;
            }
            sf = (uint32_t) json_object_dotget_number(conf, "chan_Lora_std.spread_factor");
            switch (sf) {
                case 7: ifconf.datarate = DR_LORA_SF7;
                    break;
                case 8: ifconf.datarate = DR_LORA_SF8;
                    break;
                case 9: ifconf.datarate = DR_LORA_SF9;
                    break;
                case 10: ifconf.datarate = DR_LORA_SF10;
                    break;
                case 11: ifconf.datarate = DR_LORA_SF11;
                    break;
                case 12: ifconf.datarate = DR_LORA_SF12;
                    break;
                default: ifconf.datarate = DR_UNDEFINED;
            }
            MSG("INFO: LoRa standard channel enabled, radio %i selected, IF %i Hz, %u Hz bandwidth, SF %u\n", ifconf.rf_chain, ifconf.freq_hz, bw, sf);
        }
        if (lgw_rxif_setconf(8, ifconf) != LGW_HAL_SUCCESS) {
            MSG("WARNING: invalid configuration for LoRa standard channel\n");
        }
    }

    /* set configuration for FSK channel */
    memset(&ifconf, 0, sizeof (ifconf)); /* initialize configuration structure */
    val = json_object_get_value(conf, "chan_FSK"); /* fetch value (if possible) */
    if (json_value_get_type(val) != JSONObject) {
        MSG("INFO: no configuration for FSK channel\n");
    } else {
        val = json_object_dotget_value(conf, "chan_FSK.enable");
        if (json_value_get_type(val) == JSONBoolean) {
            ifconf.enable = (bool) json_value_get_boolean(val);
        } else {
            ifconf.enable = false;
        }
        if (ifconf.enable == false) {
            MSG("INFO: FSK channel %i disabled\n", i);
        } else {
            ifconf.rf_chain = (uint32_t) json_object_dotget_number(conf, "chan_FSK.radio");
            ifconf.freq_hz = (int32_t) json_object_dotget_number(conf, "chan_FSK.if");
            bw = (uint32_t) json_object_dotget_number(conf, "chan_FSK.bandwidth");
            if (bw <= 7800) ifconf.bandwidth = BW_7K8HZ;
            else if (bw <= 15600) ifconf.bandwidth = BW_15K6HZ;
            else if (bw <= 31200) ifconf.bandwidth = BW_31K2HZ;
            else if (bw <= 62500) ifconf.bandwidth = BW_62K5HZ;
            else if (bw <= 125000) ifconf.bandwidth = BW_125KHZ;
            else if (bw <= 250000) ifconf.bandwidth = BW_250KHZ;
            else if (bw <= 500000) ifconf.bandwidth = BW_500KHZ;
            else ifconf.bandwidth = BW_UNDEFINED;
            ifconf.datarate = (uint32_t) json_object_dotget_number(conf, "chan_FSK.datarate");
            MSG("INFO: FSK channel enabled, radio %i selected, IF %i Hz, %u Hz bandwidth, %u bps datarate\n", ifconf.rf_chain, ifconf.freq_hz, bw, ifconf.datarate);
        }
        if (lgw_rxif_setconf(9, ifconf) != LGW_HAL_SUCCESS) {
            MSG("WARNING: invalid configuration for FSK channel\n");
        }
    }
    json_value_free(root_val);
    return 0;
}

int parse_gateway_configuration(const char * conf_file) {
    const char conf_obj[] = "gateway_conf";
    JSON_Value *root_val;
    JSON_Object *root = NULL;
    JSON_Object *conf = NULL;
    const char *str; /* pointer to sub-strings in the JSON data */
    unsigned long long ull = 0;

    /* try to parse JSON */
    root_val = json_parse_file_with_comments(conf_file);
    root = json_value_get_object(root_val);
    if (root == NULL) {
        MSG("ERROR: %s id not a valid JSON file\n", conf_file);
        exit(EXIT_FAILURE);
    }
    conf = json_object_get_object(root, conf_obj);
    if (conf == NULL) {
        MSG("INFO: %s does not contain a JSON object named %s\n", conf_file, conf_obj);
        return -1;
    } else {
        MSG("INFO: %s does contain a JSON object named %s, parsing gateway parameters\n", conf_file, conf_obj);
    }

    /* getting network parameters (only those necessary for the packet logger) */
    str = json_object_get_string(conf, "gateway_ID");
    if (str != NULL) {
        sscanf(str, "%llx", &ull);
        lgwm = ull;
        MSG("INFO: gateway MAC address is configured to %016llX\n", ull);
    }

    json_value_free(root_val);
    return 0;
}

void open_log(void) {
    int i;
    char iso_date[20];

    strftime(iso_date, ARRAY_SIZE(iso_date), "%Y%m%dT%H%M%SZ", gmtime(&now_time)); /* format yyyymmddThhmmssZ */
    log_start_time = now_time; /* keep track of when the log was started, for log rotation */

    sprintf(log_file_name, "pktlog_%s_%s.csv", lgwm_str, iso_date);
    log_file = fopen(log_file_name, "a"); /* create log file, append if file already exist */
    if (log_file == NULL) {
        MSG("ERROR: impossible to create log file %s\n", log_file_name);
        exit(EXIT_FAILURE);
    }

    i = fprintf(log_file, "\"gateway ID\",\"node MAC\",\"UTC timestamp\",\"us count\",\"frequency\",\"RF chain\",\"RX chain\",\"status\",\"size\",\"modulation\",\"bandwidth\",\"datarate\",\"coderate\",\"RSSI\",\"SNR\",\"payload\",\"messageType\",\"AppEUI\",\"DevEUI\",\"DevNonce\",\"MIC\",\"DevAddr\",\"AppNonce\",\"NetID\",\"DLSettings\",\"RxDelay\",\"CFList\",\"PHYPayload\",\"MHDR\",\"MACPayload\",\"FCtrl\",\"FHDR\",\"FCnt\",\"FPort\",\"FRMPayload\",\"FOpts\"\n");
    if (i < 0) {
        MSG("ERROR: impossible to write to log file %s\n", log_file_name);
        exit(EXIT_FAILURE);
    }

    MSG("INFO: Now writing to log file %s\n", log_file_name);
    return;
}

/* describe command line options */
void usage(void) {
    printf("*** Library version information ***\n%s\n\n", lgw_version_info());
    printf("Available options:\n");
    printf(" -h print this help\n");
    printf(" -r <int> rotate log file every N seconds (-1 disable log rotation)\n");
}

/** Define structure for DeviceList */
struct dl_device {
    uint64_t DEV_ADDR;
    double BASE_RSSI;
    struct dl_device *next;
};

/** 
 * Statically defined fields contain time stamp record TIMESTAMP, device address  
 * DEV_ADDR, received signal strength Indicator RSSI, base received signal strength 
 * Indicator BASE_RSSI, variance for base (RSSI) VARIANCE and payload from message 
 * PHY_PAYLOAD. This values are captured from LoRaWAN packet.
 */
UR_FIELDS(
        uint32 SIZE,
        uint32 SF,
        uint32 BAD_WIDTH,
        uint32 CODE_RATE,
        uint64 TIMESTAMP,
        string PHY_PAYLOAD,
        double RSSI
        //        string DEV_ADDR,
        //        double BASE_RSSI,
        //        double VARIANCE
        //        string GW_ID,
        //        string NODE_MAC,
        //        uint32 US_COUNT,
        //        uint32 FRQ,
        //        uint32 RF_CHAIN,
        //        uint32 RX_CHAIN,
        //        string STATUS,
        //        string MOD,
        //        double SNR,
        //        string APP_EUI,
        //        string APP_NONCE,
        //        string DEV_EUI,
        //        string DEV_NONCE,
        //        string FCTRL,
        //        string FHDR,
        //        string F_OPTS,
        //        string F_PORT,
        //        string FRM_PAYLOAD,
        //        string LORA_PACKET,
        //        string MAC_PAYLOAD,
        //        string MHDR,
        //        string MIC,
        //        string NET_ID,
        //        uint64 AIR_TIME
        )

trap_module_info_t *module_info = NULL;


/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("LoRaWAN Detection - Change distance", \
        "This detector serves for detection changing distance between device and gateway. Detection is for " \
        "fixed-position devices, if the attacker transfers the device, the RSSI (Received Signal Strength Indication) changes. " \
        "This may vary depending on the environment, such as weather. Therefore, it is possible to set the deviation for RSSI. " \
        "Base RSSI value is defined by the first received message from device to detector.", 1, 1)

/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
    PARAM('a', "variance", "Defines explicit variance, default value 10% (0.1).", required_argument, "double")
/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */

static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

/**
 * Function trap finalization and print error.
 */
void trap_fin(char *arg) {
    fprintf(stderr, arg);
    TRAP_DEFAULT_FINALIZATION();
}

/** ---- MAIN ----- */
int main(int argc, char **argv) {
    /** SectionFields LoRa logger */
    int i, j, g; /* loop and temporary variables */
    struct timespec sleep_time = {0, 3000000}; /* 3 ms */

    char buff[3];
    char payload[10000];

    /* clock and log rotation management */
    int log_rotate_interval = 3600; /* by default, rotation every hour */
    int time_check = 0; /* variable used to limit the number of calls to time() function */
    unsigned long pkt_in_log = 0; /* count the number of packet written in each log file */

    /* configuration file related */
    const char global_conf_fname[] = "global_conf.json"; /* contain global (typ. network-wide) configuration */
    const char local_conf_fname[] = "local_conf.json"; /* contain node specific configuration, overwrite global parameters for parameters that are defined in both */
    const char debug_conf_fname[] = "debug_conf.json"; /* if present, all other configuration files are ignored */

    /* allocate memory for packet fetching and processing */
    struct lgw_pkt_rx_s rxpkt[16]; /* array containing up to 16 inbound packets metadata */
    struct lgw_pkt_rx_s *p; /* pointer on a RX packet */
    int nb_pkt;

    /* local timestamp variables until we get accurate GPS time */
    struct timespec fetch_time;
    char fetch_timestamp[30];
    struct tm * x;

    /* parse command line options */
    //    while ((i = getopt (argc, argv, "hr:")) != -1) {
    //        switch (i) {
    //            case 'h':
    //                usage();
    //                return EXIT_FAILURE;
    //                break;
    //
    //            case 'r':
    //                log_rotate_interval = atoi(optarg);
    //                if ((log_rotate_interval == 0) || (log_rotate_interval < -1)) {
    //                    MSG( "ERROR: Invalid argument for -r option\n");
    //                    return EXIT_FAILURE;
    //                }
    //                break;
    //
    //            default:
    //                MSG("ERROR: argument parsing use -h option for help\n");
    //                usage();
    //                return EXIT_FAILURE;
    //        }
    //    }

    /** endSection */

    /* configure signal handling */
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigact.sa_handler = sig_handler;
    sigaction(SIGQUIT, &sigact, NULL);
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    /* configuration files management */
    if (access(debug_conf_fname, R_OK) == 0) {
        /* if there is a debug conf, parse only the debug conf */
        MSG("INFO: found debug configuration file %s, other configuration files will be ignored\n", debug_conf_fname);
        parse_SX1301_configuration(debug_conf_fname);
        parse_gateway_configuration(debug_conf_fname);
    } else if (access(global_conf_fname, R_OK) == 0) {
        /* if there is a global conf, parse it and then try to parse local conf  */
        MSG("INFO: found global configuration file %s, trying to parse it\n", global_conf_fname);
        parse_SX1301_configuration(global_conf_fname);
        parse_gateway_configuration(global_conf_fname);
        if (access(local_conf_fname, R_OK) == 0) {
            MSG("INFO: found local configuration file %s, trying to parse it\n", local_conf_fname);
            parse_SX1301_configuration(local_conf_fname);
            parse_gateway_configuration(local_conf_fname);
        }
    } else if (access(local_conf_fname, R_OK) == 0) {
        /* if there is only a local conf, parse it and that's all */
        MSG("INFO: found local configuration file %s, trying to parse it\n", local_conf_fname);
        parse_SX1301_configuration(local_conf_fname);
        parse_gateway_configuration(local_conf_fname);
    } else {
        MSG("ERROR: failed to find any configuration file named %s, %s or %s\n", global_conf_fname, local_conf_fname, debug_conf_fname);
        return EXIT_FAILURE;
    }

    /* starting the concentrator */
    i = lgw_start();
    if (i == LGW_HAL_SUCCESS) {
        MSG("INFO: concentrator started, packet can now be received\n");
    } else {
        MSG("ERROR: failed to start the concentrator\n");
        return EXIT_FAILURE;
    }

    /* transform the MAC address into a string */
    sprintf(lgwm_str, "%08X%08X", (uint32_t) (lgwm >> 32), (uint32_t) (lgwm & 0xFFFFFFFF));

    /* opening log file and writing CSV header*/
    time(&now_time);
    open_log();


    int ret;
    signed char opt;

    /** 
     * Default fields for calculate variance
     */
    double va = 0.1;

    /* **** TRAP initialization **** */

    /*
     * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
     * definitions on the lines 118 and 131 of this file. It also creates a string with short_opt letters for getopt
     * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
     */
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    /*
     * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
     */
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

    /*
     * Register signal handler.
     */
    TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

    /*
     * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
     * This macro is defined in config.h file generated by configure script
     */
    while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
            case 'a':
                sscanf(optarg, "%lf", &va);
                if ((va >= 0) && (va <= 1))
                    break;
                trap_fin("Invalid arguments variance 0.0 - 1.0\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                return -1;
            default:
                trap_fin("Invalid arguments.\n");
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
                return -1;
        }
    }

    /** Create Output UniRec templates */
    ur_template_t *out_tmplt = ur_create_output_template(0, "SIZE,SF,BAD_WIDTH,CODE_RATE,TIMESTAMP,PHY_PAYLOAD,RSSI", NULL);
    if (out_tmplt == NULL) {
        //        ur_free_template(in_tmplt);
        ur_free_template(out_tmplt);
        fprintf(stderr, "Error: Output template could not be created.\n");
        return -1;
    }

    /** Allocate memory for output record */
    void *out_rec = ur_create_record(out_tmplt, MAX_MSG_SIZE);
    if (out_rec == NULL) {
        //        ur_free_template(in_tmplt);
        ur_free_template(out_tmplt);
        ur_free_record(out_rec);
        fprintf(stderr, "Error: Memory allocation problem (output record).\n");
        return -1;
    }
    
    
    while ((quit_sig != 1) && (exit_sig != 1) && (!stop)) {
        /* fetch packets */
        nb_pkt = lgw_receive(ARRAY_SIZE(rxpkt), rxpkt);
        if (nb_pkt == LGW_HAL_ERROR) {
            MSG("ERROR: failed packet fetch, exiting\n");
            return EXIT_FAILURE;
        } else if (nb_pkt == 0) {
            clock_nanosleep(CLOCK_MONOTONIC, 0, &sleep_time, NULL); /* wait a short time if no packets */
        } else {
            /* local timestamp generation until we get accurate GPS time */
            clock_gettime(CLOCK_REALTIME, &fetch_time);
            x = gmtime(&(fetch_time.tv_sec));
            sprintf(fetch_timestamp, "%04i-%02i-%02i %02i:%02i:%02i.%03liZ", (x->tm_year) + 1900, (x->tm_mon) + 1, x->tm_mday, x->tm_hour, x->tm_min, x->tm_sec, (fetch_time.tv_nsec) / 1000000); /* ISO 8601 format */
        }

        /* log packets */
        for (i = 0; i < nb_pkt; ++i) {
            p = &rxpkt[i];

            /* writing gateway ID */
            fprintf(log_file, "\"%08X%08X\",", (uint32_t) (lgwm >> 32), (uint32_t) (lgwm & 0xFFFFFFFF));

            /* writing node MAC address */
            fputs("\"\",", log_file); // TODO: need to parse payload

            /* writing UTC timestamp*/
            fprintf(log_file, "\"%s\",", fetch_timestamp);
            // TODO: replace with GPS time when available

            /* writing internal clock */
            fprintf(log_file, "%10u,", p->count_us);

            /* writing RX frequency */
            fprintf(log_file, "%10u,", p->freq_hz);

            /* writing RF chain */
            fprintf(log_file, "%u,", p->rf_chain);

            /* writing RX modem/IF chain */
            fprintf(log_file, "%2d,", p->if_chain);

            /* writing status */
            switch (p->status) {
                case STAT_CRC_OK: fputs("\"CRC_OK\" ,", log_file);
                    break;
                case STAT_CRC_BAD: fputs("\"CRC_BAD\",", log_file);
                    break;
                case STAT_NO_CRC: fputs("\"NO_CRC\" ,", log_file);
                    break;
                case STAT_UNDEFINED: fputs("\"UNDEF\"  ,", log_file);
                    break;
                default: fputs("\"ERR\"    ,", log_file);
            }

            /* writing payload size */
            fprintf(log_file, "%u,", p->size);

            /* writing modulation */
            switch (p->modulation) {
                case MOD_LORA: fputs("\"LORA\",", log_file);
                    break;
                case MOD_FSK: fputs("\"FSK\" ,", log_file);
                    break;
                default: fputs("\"ERR\" ,", log_file);
            }

            /* writing bandwidth */
            uint32_t band_width = -1;
            switch (p->bandwidth) {
                case BW_500KHZ: band_width = 500000;
                    break;
                case BW_250KHZ: band_width = 250000;
                    break;
                case BW_125KHZ: band_width = 125000;
                    break;
                case BW_62K5HZ: band_width = 62500;
                    break;
                case BW_31K2HZ: band_width = 31200;
                    break;
                case BW_15K6HZ: band_width = 15600;
                    break;
                case BW_7K8HZ: band_width = 7800;
                    break;
                case BW_UNDEFINED: band_width = 0;
                    break;
                default: band_width = -1;
            }

            /* writing datarate */
            uint32_t sf = -1;
            if (p->modulation == MOD_LORA) {
                switch (p->datarate) {
                    case DR_LORA_SF7: sf = 7;
                        break;
                    case DR_LORA_SF8: sf = 8;
                        break;
                    case DR_LORA_SF9: sf = 9;
                        break;
                    case DR_LORA_SF10: sf = 10;
                        break;
                    case DR_LORA_SF11: sf = 11;
                        break;
                    case DR_LORA_SF12: sf = 12;
                        break;
                    default: sf = -1;
                }
            } else if (p->modulation == MOD_FSK) {
                sf = p->datarate;
            } else {
                sf = -1;
            }

            /* writing coderate */
            uint32_t code_rate = -1;
            switch (p->coderate) {
                case CR_LORA_4_5: code_rate = 5;
                    break;
                case CR_LORA_4_6: code_rate = 6;
                    break;
                case CR_LORA_4_7: code_rate = 7;
                    break;
                case CR_LORA_4_8: code_rate = 8;
                    break;
                case CR_UNDEFINED: code_rate = 0;
                    break;
                default: code_rate = -1;
            }

            /* writing packet RSSI */
            fprintf(log_file, "%+.0f,", p->rssi);

            /* writing packet average SNR */
            fprintf(log_file, "%+5.1f,", p->snr);

            /* writing hex-encoded payload (bundled in 32-bit words) */
            fputs("\"", log_file);
            for (j = 0; j < p->size; ++j) {
                if ((j > 0) && (j % 4 == 0)) fputs("-", log_file);
                fprintf(log_file, "%02X", p->payload[j]);
            }

	    /* writing payload to char */
            //payload = (char *) malloc(1000);
            for(g = 0; g < p->size; ++g){
                sprintf(buff, "%02X", p->payload[g]);
                buff[2] = '\0';
                strcat(payload, buff);
            }

            /* end of log file line */
            fputs("\"\n", log_file);
            fflush(log_file);
            ++pkt_in_log;
            
            /* set RSSI */
            ur_set(out_tmplt, out_rec, F_BAD_WIDTH, band_width);
            ur_set(out_tmplt, out_rec, F_SIZE, p->size);
            ur_set(out_tmplt, out_rec, F_RSSI, (double) p->rssi);
            ur_set(out_tmplt, out_rec, F_CODE_RATE, code_rate);
	    ur_set(out_tmplt, out_rec, F_SF, sf);
	    ur_set(out_tmplt, out_rec, F_TIMESTAMP, time(NULL));
	    ur_set_string(out_tmplt, out_rec, F_PHY_PAYLOAD, payload);

	    //free(payload);
	    //payload = NULL;
	    payload[0] = '\0';

            /* send data */
            ret = trap_send(0, out_rec, MAX_MSG_SIZE);
            TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
        }

        /* check time and rotate log file if necessary */
        ++time_check;
        if (time_check >= 8) {
            time_check = 0;
            time(&now_time);
            if (difftime(now_time, log_start_time) > log_rotate_interval) {
                fclose(log_file);
                MSG("INFO: log file %s closed, %lu packet(s) recorded\n", log_file_name, pkt_in_log);
                pkt_in_log = 0;
                open_log();
            }
        }
    }

    /** Create Input UniRec templates */
    //    ur_template_t *in_tmplt = ur_create_input_template(0, "TIMESTAMP,RSSI,PHY_PAYLOAD", NULL);
    //    if (in_tmplt == NULL) {
    //        ur_free_template(in_tmplt);
    //        fprintf(stderr, "Error: Input template could not be created.\n");
    //        return -1;
    //    }

    /**  
     * Main processing loop
     * Read data from input, process them and write to output  
     */
    /*while (!stop) {
        const void *in_rec;
        uint16_t in_rec_size;

        /** 
         * Receive data from input interface 0.
         * Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
         */
        //        ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

        /** Handle possible errors */
        //        TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

        /** Initialization physical payload for parsing and reversing octet fields. */
        //        lr_initialization(ur_get_ptr(in_tmplt, in_rec, F_PHY_PAYLOAD));

        /** Identity message type */
        //        if (lr_is_join_accept_message()) {
        //            ur_set_string(out_tmplt, out_rec, F_DEV_ADDR, DevAddr);
        //        } else if (lr_is_data_message()) {
        //            ur_set_string(out_tmplt, out_rec, F_DEV_ADDR, DevAddr);
        //        }

        /** 
         * DeviceList
         * Information is retrieved from incoming physical payload (PHYPayload) by parsing 
         * and revers octets. Each row in DeviceList contains device a BASE_RSSI of 
         * received message. The device address (DevAddr) is used as the index.
         */

        /** 
         * Load last data from Device
         */

        //        if (pre != NULL) {
        //            /**
        //             * Detection change distance
        //             * The example shows the attacker's identification where the detector is set 
        //             * to 10% variance. This means that for -119 dBm is variance -11.9 dBm. 
        //             * The minimum value is -130.9 dBm and maximum -107.1 dBm. An attacker is 
        //             * therefore detected because it does not fall within the range.
        //             */
        //            
        //            if (!(((pre->BASE_RSSI + variance) <= ur_get(in_tmplt, in_rec, F_RSSI)) && (ur_get(in_tmplt, in_rec, F_RSSI) <= (pre->BASE_RSSI - variance)))) {
        //                ur_set(out_tmplt, out_rec, F_BASE_RSSI, pre->BASE_RSSI);
        //                ur_set(out_tmplt, out_rec, F_VARIANCE, va);
        //                ret = trap_send(0, out_rec, MAX_MSG_SIZE);
        //
        //                TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
        //            }
        //
        //        }

        /** 
         * Free lora_packet and output record
         */
       /* lr_free();
    } */


    /* **** Cleanup **** */

    /** 
     * Do all necessary cleanup in libtrap before exiting
     */
    TRAP_DEFAULT_FINALIZATION();

    /** 
     * Release allocated memory for module_info structure
     */
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    /** 
     *  Free unirec templates and output record
     */
    ur_free_record(out_rec);
    //    ur_free_template(in_tmplt);
    ur_free_template(out_tmplt);
    ur_finalize();

    /**
     * Free logger 
     */
    i = lgw_stop();
    fclose(log_file);


    return 0;
}
