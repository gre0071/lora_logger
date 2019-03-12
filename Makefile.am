ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=lora_logger_module
lora_logger_module_SOURCES=lora_logger_module.c fields.c fields.h lora_packet.c lora_packet.h device_list.c device_list.h parson.c parson.h aes/aes.c aes/aes.h
lora_logger_module_LDADD=-lunirec -ltrap -lrt -lm
include ./aminclude.am
