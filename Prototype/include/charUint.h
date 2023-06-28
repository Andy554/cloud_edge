/**
 * @file charUint.h
 * @author Jingyuan YANG (youngjunggar40021@gmail.com)
 * @brief Conversion between 32-bit int and 8-bit char
 * @version 0.1
 * @date 2023-5-5
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include "stdint.h"

/**
* @brief converting usigned int to char
* 
* @param srcInt the chunk address
* @param chunkBuffer the chunk buffer
*/
void uint32_to_uint8(uint32_t srcInt, uint8_t* tarChar);

/**
* @brief converting char to usigned int
* 
* @param srcInt the chunk address
* @param chunkBuffer the chunk buffer
*/
void uint8_to_uint32(uint8_t* srcChar, uint32_t tarInt);
