//
// Created by 61485 on 2026/1/14.
//
#include <pbc/pbc.h>
#ifndef CPABE_TOOLS_H
#define CPABE_TOOLS_H


unsigned char * ElementToBytes(element_t e) {
    int l = element_length_in_bytes(e);
    unsigned char * data = new unsigned char[l];
    element_to_bytes(data,e);
    return data;
}



#endif //CPABE_TOOLS_H