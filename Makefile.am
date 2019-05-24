ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=lora_logger
lora_logger_SOURCES=lora_logger.c fields.c fields.h lora_packet.c lora_packet.h device_list.c device_list.h parson.c parson.h aes/aes.c aes/aes.h
lora_logger_LDADD=-lunirec -ltrap -lrt -lm
include ./aminclude.am