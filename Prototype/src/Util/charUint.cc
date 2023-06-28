/**
 * @file charUint.cc
 * @author Jingyuan YANG (youngjunggar40021@gmail.com)
 * @brief Conversion between 32-bit int and 8-bit char
 * @version 0.1
 * @date 2023-5-5
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include"../include/charUint.h"

/**
* @brief converting usigned int to char
* 
* @param srcInt the chunk address
* @param chunkBuffer the chunk buffer
*/
void uint32_to_uint8(uint32_t srcInt, uint8_t* tarChar){
    tarChar[0] = (srcInt >> 0) & 255;
    tarChar[1] = (srcInt >> 8) & 255;
    tarChar[2] = (srcInt >> 16) & 255;
    tarChar[3] = (srcInt >> 24) & 255;
    return;
}

/**
* @brief converting char to usigned int
* 
* @param srcInt the chunk address
* @param chunkBuffer the chunk buffer
*/
void uint8_to_uint32(uint8_t* srcChar, uint32_t& tarInt){
    int n0 = srcChar[0];      //0~8位
    int n1 = srcChar[1];      //8~16位
    int n2 = srcChar[2];      //16~24位
    int n3 = srcChar[3];      //24~32位
    tarInt = (n0 << 0) + (n1 << 8) + (n2 << 16) + (n3 << 24);
    return;
}