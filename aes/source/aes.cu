/**
  ***********************************************************************************
  * @file   : AES.cu
  * @brief  : Main program body
  *         : Final Project: AES Encryption
  *         : CS-4981/031 
  * @date   : OCT 29 2021
  * @author : Julian Singkham, Nathan DuPont, Chip Hennig
  ***********************************************************************************
  * @attention
  *
  * Assume all operations are column major unless specified otherwise. 
  *
  ***********************************************************************************
**/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h> 
#include <time.h>
#include "aes.h"


/**
 * This struct holds timing information for time profiling
 */
struct timingData_t {
	float total;
	float encrypt;
	float decrypt;
};

// Key is written column wise
// 0 4  8 12
// 1 5  9 13
// 2 6 10 14
// 3 7 11 15
// Each element of the expanded key is 32-bits (word) which equates to a column
uint32_t *exp_key;

//======================================Methods=======================================
/**
  * @brief Calculates how long the CPU was operating
  * 
  * @param start: Pointer to the cpu time the operation started.
  * @param end: Pointer to the cpu time the operation ended.
  * 
  * @retval The length of time the cpu was operating in milliseconds
*/
float cpuTime(timespec* start, timespec* end){
	return ((1e9*end->tv_sec + end->tv_nsec) - 
			(1e9*start->tv_sec + start->tv_nsec))/1e6;
}

/**
  * @brief Transposes (rotates) the array 90 degress (row major -> column major)
  * Currently only works with a 4-word array (128-bits)
  * 
  * @param input: Pointer to the array to transpose
  * 
  * @retval NONE
  */
  __host__ __device__ void transpose(uint32_t *input) {
	uint32_t c0 = 0, c1=0, c2=0, c3=0;
	for (int i=0; i<4; i++){
		c0 |= (input[i] >> 24)		  << (8 * (3 - i));
		c1 |= (input[i] >> 16 & 0xff) << (8 * (3 - i));
		c2 |= (input[i] >> 8  & 0xff) << (8 * (3 - i));
		c3 |= (input[i] 	  & 0xff) << (8 * (3 - i));
	}
	input[0] = c0;
	input[1] = c1;
	input[2] = c2;
	input[3] = c3;
}

/**
  * @brief Step 4 of AES decryption. This operation modulo multiplies a column in 
  * Rijndael's Galois Field.
  * based on https://en.wikipedia.org/wiki/Rijndael_mix_columns#MixColumns
  * a0-3 represent the bytes of a column 
  * r0-3 are the transformed bytes
  * 
  * @param state: Pointer to the current state of the text to be decrypted
  * 
  * @retval NONE
  */
  __host__ __device__ void invMixColumns(uint32_t *state){
	// a0-3 represent the bytes of a column
	// r0-3 are the transformed bytes
	for (int i=0; i < 4; i++){
		// Read one column at a time
		uint8_t a0, a1, a2, a3;
		a0 = uint8_t(state[i] >> 24);
		a1 = uint8_t(state[i] >> 16&0xff);
		a2 = uint8_t(state[i] >> 8&0xff);
		a3 = uint8_t(state[i] &0xff);

		// calculate the transformed bytes
		uint8_t r0, r1, r2, r3;
		r0 = GMULBY14(a0) ^ GMULBY11(a1) ^ GMULBY13(a2) 
		     ^ GMULBY9(a3);  // 14*a0 + 11*a1 + 13*a2 +  9*a3
		r1 = GMULBY9(a0)  ^ GMULBY14(a1) ^ GMULBY11(a2) 
		     ^ GMULBY13(a3); //  9*a0 + 14*a1 + 11*a2 + 13*a3
		r2 = GMULBY13(a0) ^ GMULBY9(a1)  ^ GMULBY14(a2) 
		     ^ GMULBY11(a3); // 13*a0 +  9*a1 + 14*a2 + 11*a3
		r3 = GMULBY11(a0) ^ GMULBY13(a1) ^ GMULBY9(a2)  
		     ^ GMULBY14(a3); // 11*a0 + 13*a1 +  9*a2 + 14*a3

		// set the column with the calculated values
		state[i] = (uint32_t(r0) << 24) | (uint32_t(r1) << 16) | (uint32_t(r2) << 8) | (uint32_t(r3));
	}
}

/**
  * @brief Step 3 of AES encryption. This operation modulo multiplies a column in 
  * Rijndael's Galois Field.
  * based on https://en.wikipedia.org/wiki/Rijndael_mix_columns#MixColumns
  * a0-3 represent the bytes of a column 
  * r0-3 are the transformed bytes
  * 
  * @param state: Pointer to the current state of the text to be encrypted
  * 
  * @retval NONE
  */
__host__ __device__ void mixColumns(uint32_t *state){
	// Reads one column at a time
	for (int i=0; i < 4; i++){
		uint8_t a0, a1, a2, a3;
		a0 = uint8_t(state[i] >> 24); 
		a1 = uint8_t(state[i] >> 16&0xff);
		a2 = uint8_t(state[i] >> 8&0xff);
		a3 = uint8_t(state[i] &0xff);

		// calculate the transformed bytes
		uint8_t r0, r1, r2, r3;
		r0 = GMULBY2(a0) ^ GMULBY3(a1) ^  a2  		 ^ a3;			// 2*a0 + 3*a1 + a2   + a3
		r1 = a0          ^ GMULBY2(a1) ^ GMULBY3(a2) ^ a3; 			// a0   + 2*a1 + 3*a2 + a3
		r2 = a0 		 ^  a1   	   ^ GMULBY2(a2) ^ GMULBY3(a3);	// a0   + a1   + 2*a2 + 3*a3
		r3 = GMULBY3(a0) ^  a1  	   ^  a2  		 ^ GMULBY2(a3);	// 3*a0 + a1   + a2   + 2*a3

		// set the column with the calculated values
		state[i] = (uint32_t(r0) << 24) | (uint32_t(r1) << 16) | 
		           (uint32_t(r2) << 8) | (uint32_t(r3));
	}
}

/**
  * @brief Rotates a word to the right n bytes
  * 
  * @param word: Word to be rotated
  * @param n: Number of bytes to shift right
  * 
  * @retval The shifted word
  */
__host__ __device__ int rotateRight(uint32_t word, int n) {
	return word<<(32-8*n) | word>>(8*n);
  }

/**
  * @brief Rotates a word to the left n bytes
  * 
  * @param word: Word to be rotated
  * @param n: Number of bytes to shift left
  * 
  * @retval The shifted word
  */
__host__ __device__ int rotateLeft(uint32_t word, int n){
	return word>>(32-8*n) | word<<(8*n);
}

/**
  * @brief Step 1 of AES decryption. This rotates the rows of the state.
  * This operation is row major
  * 
  * @param state: Pointer to the current state of the text to be decrypted
  * 
  * @retval NONE
  */
__host__ __device__ void invShiftRows(uint32_t* state){
	transpose(state);
	for (int i = 1; i < 4; i++)
		state[i] = rotateRight(state[i], i);
	transpose(state);
}

/**
  * @brief Step 2 of AES encryption. This rotates the rows of the state.
  * This operation is row major
  * 
  * @param state: Pointer to the current state of the text to be encrypted
  * 
  * @retval NONE
  */
__host__ __device__ void shiftRows(uint32_t *state){
	transpose(state);
	for (int i = 1; i < 4; i++)
		state[i] = rotateLeft(state[i], i);
	transpose(state);
}

/**
  * @brief This operation swaps each SBOX byte into its standard form. 
  * The first hex value (16-bit) denotes the x-coordinate and
  * the second half denotes the y-coordinate.
  * 
  * @param input: The word to be substituted.
  * 
  * @retval NONE
  */
__host__ __device__ uint32_t invSubWord(uint32_t input){
	return 	uint32_t(SBOX1(input>>24))<<24 |
			uint32_t(SBOX1(input>>16&0xff))<<16 |
			uint32_t(SBOX1(input>>8&0xff))<<8 |
			uint32_t(SBOX1(input&0xff));
}

/**
  * @brief This operation swaps each byte in a word with the corresponding
  * SBOX byte. The first hex value (4-bit) denotes the x-coordinate and
  * the second half denotes the y-coordinate.
  * 
  * @param input: The word to be substituted.
  * 
  * @retval NONE
  */
__host__ __device__ uint32_t subWord(uint32_t input){
	return 	uint32_t(SBOX0(input>>24))<<24 |
			uint32_t(SBOX0(input>>16&0xff))<<16 |
			uint32_t(SBOX0(input>>8&0xff))<<8 |
			uint32_t(SBOX0(input&0xff));
}

/**
  * @brief Step 2 of AES decryption. This swaps each SBOX byte in the text 
  into its standard form. 
  * 
  * @param state: Pointer to the current state of the text to be encrypted
  * @param state_len: Length of the state (# of columns)
  * 
  * @retval NONE
  */
__host__ __device__ void invSubBytes(uint32_t *state, int state_len){
	for (int i = 0; i < state_len; i++)
		state[i] = invSubWord(state[i]);
}

/**
  * @brief Step 1 of AES encryption. This swaps each byte in the text with the 
  * corresponding SBOX byte.
  * 
  * @param state: Pointer to the current state of the text to be encrypted
  * @param state_len: Length of the state (# of columns)
  * 
  * @retval NONE
  */
__host__ __device__ void subBytes(uint32_t *state, int state_len){
	for (int i = 0; i < state_len; i++)
		state[i] = subWord(state[i]);
}

/**
  * @brief Step 4 of AES encryption and step 3 of decryption. This operation 
  * xor's each column of the text with the corresponding round key column.
  * 
  * @param state: Pointer to the current state of the text
  * @param key: Pointer to the expanded encryption key
  * @param key_id: Starting column of the expanded key to use.
  *
  * @retval NONE
  */
__host__ __device__ void addRoundKey(uint32_t *state, uint32_t *key, int key_id){
	for (int i = 0; i < 4; i++)
		state[i] ^= key[i+key_id];
}

/**
  * @brief Encrypts a message using AES encryption.
  * 
  * @param state: Pointer to the current state of the text to be encrypted
  * @param key: Pointer to the expanded encryption key
  * @param state_len: Length of the state (# of columns)
  *
  * @retval NONE
  */
__host__ __device__ void encrypt(uint32_t *state, uint32_t *key, int state_len){
	int key_id = 0;
	// Round 0 of AES only does addRoundKey
	addRoundKey(state, key, key_id);
	key_id += 4;

	for (int i = 0; i < ROUNDS-1; i++) {
		subBytes(state, state_len);
		shiftRows(state);
		mixColumns(state);
		addRoundKey(state, key, key_id);
		key_id += 4;
	}

	// The final round of AES skips mixColumns
	subBytes(state, state_len);
	shiftRows(state);
	addRoundKey(state, key, key_id);
}

/**
  * @brief Decrypts a message using AES encryption.
  * 
  * @param state: Pointer to the current state of the text to be decrypted
  * @param key: Pointer to the expanded encryption key
  * @param state_len: Length of the state (# of columns)
  *
  * @retval NONE
  */
__host__ __device__ void decrypt(uint32_t* state, uint32_t* key, int state_len) {
	int key_id = ROUNDS*4;
	// The final round of AES skips mixColumns
	//printf("\nKey ID %d", key_id);
	//printf("\nData: ");
	//for (int j=0; j<4; j++)
		//printf("0x%x ", state[j]);
	
	//printf("\nRound 10: \n");
	addRoundKey(state, key, key_id);
	//printf("\nAdd round: ");
	//for (int j=0; j<4; j++)
		//printf("0x%x ", state[j]);

	invShiftRows(state);
	//printf("\nshiftrows: ");
	//for (int j=0; j<4; j++)
		//printf("0x%x ", state[j]);

	invSubBytes(state, state_len);
	//printf("\nsubBytes : ");
	//for (int j=0; j<4; j++)
		//printf("0x%x ", state[j]);
	
	key_id -= 4;

	for (int i = 0; i < ROUNDS-1; i++) {
		//printf("\n\nRound %d: ", 10-i-1);

		addRoundKey(state, key, key_id);
		key_id -= 4;
		//printf("\nAdd round: ");
		//for (int j=0; j<4; j++)
			//printf("0x%x ", state[j]);
			
		invMixColumns(state);
		//printf("\nmix Cols : ");
		//for (int j=0; j<4; j++)
			//printf("0x%x ", state[j]);

		invShiftRows(state);
		//printf("\nshiftrows: ");
		//for (int j=0; j<4; j++)
			//printf("0x%x ", state[j]);

		invSubBytes(state, state_len);
		//printf("\nsubBytes : ");
		//for (int j=0; j<4; j++)
			//printf("0x%x ", state[j]);

	}

	// Round 0 of AES only does addRoundKey
	//printf("\n\nRound 0: ");
	addRoundKey(state, key, key_id);
	//printf("\nAdd round: ");
	//for (int j=0; j<4; j++)
		//printf("0x%x ", state[j]);
}


/**
  * @brief Returns the corresponding round constant.
  * 
  * @param i: The location of rcon to use
  *
  * @retval NONE
  */
__host__ __device__ uint32_t rcon(int i){
	return uint32_t(powx(i)) << 24;
}


/**
  * @brief Expands the key size to fit the number of ROUNDS.
  * Based on https://en.wikipedia.org/wiki/Rijndael_key_schedule
  * Only supports 128-bit key
  *
  * @param key: Pointer to the supplied encryption key
  * @param key_len: Length of the key in bits
  *
  * @retval NONE
  */
void keyExpansion(uint8_t *key, int key_len){
	//Default 128 bit key
	// NUM_WORDS = 4; // number of columns
	// ROUNDS = 10;
	// if(key_len == 192){
	// 	NUM_WORDS = 6;
	// 	ROUNDS = 12;
	// }
	// else if(key_len == 256){
	// 	NUM_WORDS = 8;
	// 	ROUNDS = 14;
	// }
	free(exp_key);
	exp_key = (uint32_t*)malloc(4*(ROUNDS+1) * sizeof(uint32_t));

	// the key occupies the first NUM_WORDS columns of the expanded key
	int i = 0;
	
	while (i < NUM_WORDS){
		exp_key[i] = uint32_t(key[i])<<24 | uint32_t(key[i+4])<<16 | uint32_t(key[i+8])<<8 | uint32_t(key[i+12]);
		i++;
	}

	// Key specified here for testing purposes
	exp_key[0] = 0x2b7e1516;
	exp_key[1] = 0x28aed2a6;
	exp_key[2] = 0xabf71588;
	exp_key[3] = 0x09cf4f3c;
	// Start with the last column, rotate, subWord, then xor with the first column of the previous block and the Rcon
	while (i < 4*(ROUNDS+1)){
		exp_key[i] = exp_key[i-1];
		exp_key[i] = rotateLeft(exp_key[i], 1);
		exp_key[i] = subWord(exp_key[i]);
		exp_key[i] ^= exp_key[i-NUM_WORDS];
		exp_key[i] ^= rcon(i/NUM_WORDS - 1);

		// XOR with the corresponding column of the previous block and the previous column.
		for (int j=1; j < 4; j++)
			exp_key[i+j] = exp_key[i+j-1] ^ exp_key[i+j-NUM_WORDS];
		
		i+=NUM_WORDS;
	}
}


/**
  * @brief Generates a random plain text file
  *
  * @param size: The size of the file in bytes
  *
  * @retval NONE
  */
void generateInput(size_t size) {
	// Open new input file
	FILE* fp = fopen("input.txt", "wb");

	// Generate random characters in the file
	for (int k = 0; k < size; k++) {
		int r = rand() % 26;
		fprintf(fp, "%c", r + 97);
	}

	// Close the file
	fclose(fp);
}


/**
  * @brief Saves the state to a specified file
  *
  * @param state: Pointer to the current state of the text to be saved
  * @param size: The size of the file in bytes
  * @param file_name: Name of the file to save to
  *
  * @retval NONE
  */
void write(uint32_t *state, int size, char *file_name, bool first_write){
	FILE *file;
	if (first_write) {
		file = fopen(file_name, "wb");
	} else {
		file = fopen(file_name, "a");
	}
	for(int i=0; i<size; i++)
		fwrite(&state[i], sizeof(char), sizeof(uint32_t), file);
	fclose(file);
}


/**
 * @brief Executes AES encryption and decryption on the CPU
 * 
 * @retval timingData_t Timing information from the exeuction run
 */
timingData_t runCPU() {
	// Create timers
	timespec tStart, tEnd;
	timespec tStartEncrypt, tEndEncrypt;
	timespec tStartDecrypt, tEndDecrypt;

	// Open the input file
	FILE* file;
	file = fopen("input.txt", "r");

	// Allocate memory for a single chunk
	uint32_t* chunk = (uint32_t*)malloc(4 * sizeof(uint32_t));	
	// Start reading in chunks of data
	bool firstWrite = true;

	// Count the total number of iterations
	int iterations = 0;
	clock_gettime(CLOCK_MONOTONIC_RAW, &tStart);
	while (fread(chunk, sizeof(uint32_t), sizeof(uint32_t), file) != 0) {
		// Encrypt the current chunk
		clock_gettime(CLOCK_MONOTONIC_RAW, &tStartEncrypt);
		encrypt(chunk, exp_key, NUM_WORDS);
		clock_gettime(CLOCK_MONOTONIC_RAW, &tEndEncrypt);
		
		// Save the current chunk to a file
		char first_file[] = "CPU_Encryption.txt";
		write(chunk, NUM_WORDS, first_file, NUM_WORDS);
		
		// Decrypt the current chunk
		clock_gettime(CLOCK_MONOTONIC_RAW, &tStartDecrypt);
		decrypt(chunk, exp_key, NUM_WORDS);
		clock_gettime(CLOCK_MONOTONIC_RAW, &tEndDecrypt);

		// Save the current chunk to a file
		char second_file[] = "CPU_Decryption.txt";
		write(chunk, NUM_WORDS, second_file, firstWrite);
		firstWrite = false;
		iterations += 1;
	}
	clock_gettime(CLOCK_MONOTONIC_RAW, &tEnd);
	
	// Close memory resources
	fclose(file);
	free(chunk);
	
	// Save the timing outputs to a struct - multiply encryption and decryption by number of iterations
	timingData_t timing = {
		cpuTime(&tStart, &tEnd), 
		cpuTime(&tStartEncrypt, &tEndEncrypt) * iterations, 
		cpuTime(&tStartDecrypt, &tEndDecrypt) * iterations
	};

	return timing;
}


/**
 * @brief Runs an encryption kernel on a GPU
 * 
 * @retval NONE
 */
__global__
void AESEncryptKernel(uint32_t* data, uint32_t* exp_key, int state_size, 
	uint32_t* encrypt_data, int numBytes) {
	int chunk_idx = (blockDim.x * blockIdx.x + threadIdx.x) * NUM_WORDS;
	int numWords = numBytes / 4;

	// Make sure that our current index is valid based on the 
	if (chunk_idx < numWords) {
		uint32_t chunk[4];
		
		// Load required data into registers
		for(int i = 0; i < state_size; i++) {
			chunk[i] = data[chunk_idx + i];
		}
	
		// Encrypt the provided data
		encrypt(chunk, exp_key, state_size);

		// Write the encrypted data to the buffer
		for(int i = 0; i < state_size; i++) {
			encrypt_data[chunk_idx + i] = chunk[i];
		}
	}
}


/**
 * @brief Runs a decryption kernel on a GPU
 * 
 * @retval NONE
 */
__global__
void AESDecryptKernel(uint32_t* data, uint32_t* exp_key, int state_size, 
	uint32_t* decrypt_data, int numBytes) {
	int chunk_idx = (blockDim.x * blockIdx.x + threadIdx.x) * NUM_WORDS;
	int numWords = numBytes / 4;

	// Make sure that our current index is valid based on the 
	if (chunk_idx < numWords) {
		uint32_t chunk[4];
		
		// Load required data into registers
		for(int i = 0; i < state_size; i++) {
			chunk[i] = data[chunk_idx + i];
		}
	
		// Decrypt the provided data
		decrypt(chunk, exp_key, state_size);

		// Write the encrypted data to the buffer
		for(int i = 0; i < state_size; i++) {
			decrypt_data[chunk_idx + i] = chunk[i];
		}
	}
}


/**
 * @brief Handles the configuration and memory management for launching calculation
 * kernels on a GPU
 * 
 * @param file_size Size of the file in bytes
 * @retval timingData_t Timing information from the function execution
 */
timingData_t runGPU(size_t file_size) {
	// Allocate memory for storing data on the host
	uint32_t* data = (uint32_t*)malloc(file_size); // Plaintext
	uint32_t* encrypt_data = (uint32_t*)malloc(file_size); // Encrypted text
	uint32_t* decrypt_data = (uint32_t*)malloc(file_size); // Decrypted text
	
	// Allocate memory for storing data on the device
	uint32_t* d_data;
	uint32_t* d_encrypt_data;
	uint32_t* d_decrypt_data;
	uint32_t* d_exp_key;

	// Create timers
	cudaEvent_t tStart, tEnd;
	cudaEvent_t tStartEncrypt, tEndEncrypt;
	cudaEvent_t tStartDecrypt, tEndDecrypt;

	// Create events for the timers
	cudaEventCreate(&tStart);
	cudaEventCreate(&tEnd);
	cudaEventCreate(&tStartEncrypt);
	cudaEventCreate(&tEndEncrypt);
	cudaEventCreate(&tStartDecrypt);
	cudaEventCreate(&tEndDecrypt);
	
	// Read plaintext from input.txt into data
	FILE* file = fopen("input.txt", "r");
	fread(data, sizeof(uint32_t), file_size / sizeof(uint32_t), file);
	fclose(file);

	// Start timing the entire kernel
	cudaEventRecord(tStart);

	// Malloc the arrays on the device
	cudaMalloc(&d_data, file_size);
	cudaMalloc(&d_encrypt_data, file_size);
	cudaMalloc(&d_decrypt_data, file_size);

	// Calculate the key size
	size_t key_size = 4 * (ROUNDS + 1) * sizeof(uint32_t); 

	// Allocate memory for the key
	cudaMalloc(&d_exp_key, key_size);

	// Copy the data and expanded key to the device
	cudaMemcpy(d_data, data, file_size, cudaMemcpyHostToDevice);
	cudaMemcpy(d_exp_key, exp_key, key_size, cudaMemcpyHostToDevice);

	// Determine the size of the blocks and grid
	dim3 DimGrid(ceil((file_size / 1024.0)), 1, 1);
	dim3 DimBlock(1024, 1, 1);
	
	// Run the encryption kernel and time it's execution
	cudaEventRecord(tStartEncrypt);
	AESEncryptKernel<<<DimGrid, DimBlock>>>(d_data, d_exp_key, NUM_WORDS, 
		d_encrypt_data, file_size);
	cudaEventRecord(tEndEncrypt);

	// Run the decryption kernel and time it's execution
	cudaEventRecord(tStartDecrypt);
	AESDecryptKernel<<<DimGrid, DimBlock>>>(d_encrypt_data, d_exp_key, NUM_WORDS, 
		d_decrypt_data, file_size);
	cudaEventRecord(tEndDecrypt);

	// Copy the encrypted and decrypted data to the host
	cudaMemcpy(encrypt_data, d_encrypt_data, file_size, cudaMemcpyDeviceToHost);
	cudaMemcpy(decrypt_data, d_decrypt_data, file_size, cudaMemcpyDeviceToHost);

	// Record the final time
	cudaEventRecord(tEnd);
	cudaEventSynchronize(tEnd);

	// Save the encrypted and decrypted data to a file
	file = fopen("GPU_Encryption.txt", "wb");
	fwrite(encrypt_data, sizeof(char), file_size, file);
	fclose(file);
	file = fopen("GPU_Decryption.txt", "wb");
	fwrite(decrypt_data, sizeof(char), file_size, file);
	fclose(file);

	// Record the final times
	float totalTime = 0;
	float encryptTime = 0;
	float decryptTime = 0;
	cudaEventElapsedTime(&totalTime, tStart, tEnd);
	cudaEventElapsedTime(&encryptTime, tStartEncrypt, tEndEncrypt);
	cudaEventElapsedTime(&decryptTime, tStartDecrypt, tEndDecrypt);

	// Free host memory
	free(data);
	free(encrypt_data);
	free(decrypt_data);

	// Free CUDA memory
	cudaFree(d_data);
	cudaFree(d_encrypt_data);
	cudaFree(d_decrypt_data);
	cudaFree(d_exp_key);

	// Save the timing outputs to a struct
	timingData_t timing = {
		totalTime, 
		encryptTime,
		decryptTime
	};

	return timing;
}


/**
  * @brief Main function to execute the program
  * 
  * @param argc: Quantity of arguments supplied to the program
  * @param argv: Array of arguments supplied to the program
  * 
  * @retval int Return code of the program
  */
int main(int argc, char* argv[]){
	// Define a key and expand it for encryption
	uint8_t key[128] = "PURPLE SIDEKICKS"; // Not used
	keyExpansion(key, 128);
	
	// Create an input file of random bytes
	size_t file_size = 100000;
	generateInput(file_size);

	// Define the number of iterations to perform
	size_t iterations = 10;

	// Create variables to store the timing information
	timingData_t cpuTimingArr[iterations];
	timingData_t gpuTimingArr[iterations];

	// Iterate through and run AES for the desired iterations
	for (size_t i = 0; i < iterations; i++) {
		// Run the CPU implementation 
		cpuTimingArr[i] = runCPU();

		// Run the GPU implementation
		gpuTimingArr[i] = runGPU(file_size);	
	}


	// Open the file to write data to
	FILE* timing_file = fopen("timing.txt", "w");

	fprintf(timing_file, "Total Bytes: %ld\n\n", file_size);

	// Iterate through and calculate CPU metrics
	fprintf(timing_file, "CPU:\n");

	float avgTotal = 0;
	float avgEncrypt = 0;
	float avgDecrypt = 0;

	for (size_t i = 0; i < iterations; i++) {
		// Run the CPU implementation
		timingData_t time = cpuTimingArr[i];
		fprintf(timing_file, "\tTrial %ld | Total: %f\t\tEncrypt: %f\t\tDecrypt: %f\n", i, time.total, time.encrypt, time.decrypt);

		avgTotal += time.total;
		avgEncrypt += time.encrypt;
		avgDecrypt += time.decrypt;
	}

	fprintf(timing_file, "\tAverage | Total: %f\t\tEncrypt: %f\t\tDecrypt: %f\n", avgTotal / iterations, avgEncrypt / iterations, avgDecrypt / iterations);

	// Iterate through and calculate GPU metrics
	fprintf(timing_file, "GPU:\n");

	avgTotal = 0;
	avgEncrypt = 0;
	avgDecrypt = 0;

	// Iterate through and calculate GPU metrics
	for (size_t i = 0; i < iterations; i++) {
		// Run the GPU implementation
		timingData_t time = gpuTimingArr[i];
		fprintf(timing_file, "\tTrial %ld | Total: %f\t\tEncrypt: %f\t\tDecrypt: %f\n", i, time.total, time.encrypt, time.decrypt);

		avgTotal += time.total;
		avgEncrypt += time.encrypt;
		avgDecrypt += time.decrypt;
	}

	fprintf(timing_file, "\tAverage | Total: %f\t\tEncrypt: %f\t\tDecrypt: %f\n", avgTotal / iterations, avgEncrypt / iterations, avgDecrypt / iterations);

	// Close the file
	fclose(timing_file);

	return 0;
}





