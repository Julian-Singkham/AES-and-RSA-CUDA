#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include <openssl/bn.h>

float cpu_time(timespec* start, timespec* end){
    return ((1e9*end->tv_sec + end->tv_nsec) -(1e9*start->tv_sec + start->tv_nsec))/1e6;
};


// Declare constant values used in GPU kernel
__constant__ long const_key;
__constant__ long const_n;

// RSA encryption / decryption GPU kernel
__global__ void rsa(int *num, int *result, long size) {
	int id = blockDim.x * blockIdx.x + threadIdx.x;
	// Verify index fits into array of characters being encrypted / decrypted
	if (id < size) {
		long temp = 1;
		long k = num[id];
		
		// Exponent multiplication with mod
		for (int i = 0; i < const_key; i++) {
			temp *= k;
			temp = temp % const_n;
		}
		result[id] = temp;
	}
}

// Calculates the decryption key
int create_private_decrypt(int phi_n, int e) {
    int inv;
    int q, r, r1 = phi_n, r2 = e, t, t1 = 0, t2 = 1;
 
    while (r2 > 0) {
        q = r1 / r2;
        r = r1 - q * r2;
        r1 = r2;
        r2 = r;
 
        t = t1 - q * t2;
        t1 = t2;
        t2 = t;
    }
 
    if (r1 == 1) {
        inv = t1;
    }
 
    if (inv < 0) {
        inv = inv + phi_n;
    }
 
    return inv;
}

// Calculates greatest common denominator of two numbers
int gcd(int a, int b) {
    int q, r1, r2, r;
 
    if (a > b) {
        r1 = a;
        r2 = b;
    } else {
        r1 = b;
        r2 = a;
    }
 
    while (r2 > 0) {
        q = r1 / r2;
        r = r1 - q * r2;
        r1 = r2;
        r2 = r;
    }
 
    return r1;
}

// Creating random character file
void generate_input(long size) {
	printf("Generating input file.\n");
	FILE *fp = fopen("input.txt", "wb");
    for (int k = 0; k < size; k++) {
        int r = rand() % 26;
        fprintf(fp, "%c", r + 97);
    }
    fprintf(fp, "\n");
    fclose(fp);
}

int main(int argc, char* argv[]){
	if (argc > 1) {
		// declaring variables
		long numChars = strtol(argv[1], NULL, 10);
		long p, q, n, t, e, d;
		int cpu_array[numChars+2], gpu_array[numChars+2], encrypted_message[numChars+2];
		time_t tt;
		char msg[numChars+2];

		// Initializing RNG and generating test input
		srand((unsigned) time(&tt));
		generate_input(numChars);

		// Prime numbers (from prime number generator)
		p = 157;
		q = 373;

		n = p * q;
		// phi of n
		t = (p - 1) * (q - 1);

		// Read in data from file
		FILE *f = fopen("input.txt", "r");
		if (fgets(msg, numChars+2, f) != NULL) {
			printf("Reading input file...done(");
		}
		fclose(f);
		msg[numChars] = '\0';
		printf("numChars: %ld)\n\n", numChars);

		// Transfer data to cpu and gpu processing arrays
		for (int i = 0; msg[i] != '\0'; i++) {
			cpu_array[i] = msg[i] - 96;
			gpu_array[i] = msg[i] - 96;
		}

		// Calculating the public and private exponents
		do {
			e = rand() % (t - 2) + 2; // 1 < e < t
		} while (gcd(e, t) != 1);
		d = create_private_decrypt(t, e);
		// e = 48335;
		// d = 51455;

		printf("Public Exponent e: %ld\n",e);
		printf("Private Exponent d: %ld\n",d);

		// CPU Encryption
		timespec ts, te;
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
		
		for (int i = 0; i < numChars; i++) {
			long pt = cpu_array[i];
			long k = 1;
			// Exponent multiplication with mod
			for (int j = 0; j < e; j++) {
				k = k * pt;
				k = k % n;
			}
			encrypted_message[i] = k + 96;
		}

		//finish CPU encryption benchmarking
		clock_gettime(CLOCK_MONOTONIC_RAW, &te);
		printf("\nCPU Encryption Ellapsed Time: %f\n", cpu_time(&ts, &te));

		// CPU Decryption
		clock_gettime(CLOCK_MONOTONIC_RAW, &ts);

		for (int i = 0; i < numChars; i++) {
			long ct = encrypted_message[i] - 96;
			long k = 1;

			// Exponent multiplication with mod
			for (int j = 0; j < d; j++) {
				k = k * ct;
				k = k % n;
			}
			cpu_array[i] = k + 96;
		}

		//finish CPU decryption benchmarking
		clock_gettime(CLOCK_MONOTONIC_RAW, &te);
		printf("CPU Decryption Ellapsed Time: %f\n", cpu_time(&ts, &te));
		
		// Create decrypted file
		FILE *fp = fopen("decrypted_cpu.txt", "wb");
		for (int k = 0; k < numChars; k++) {
			fprintf(fp, "%c", cpu_array[k]);
		}
		fprintf(fp, "\n");
		fclose(fp);

		// GPU Encryption
		cudaEvent_t start, stop;
		cudaEventCreate(&start);
		cudaEventCreate(&stop);
		int *d_num, *d_res;
		// Allocating GPU memory
		cudaMalloc((void **) &d_num, numChars * sizeof(int));
		cudaMalloc((void **) &d_res, numChars * sizeof(int));
		// Copy data to GPU
		cudaMemcpy(d_num, gpu_array, numChars * sizeof(int), cudaMemcpyHostToDevice);
		cudaMemcpyToSymbol(const_key, &e, sizeof(long));
		cudaMemcpyToSymbol(const_n, &n, sizeof(long));
		// Determine block dimensions
		dim3 blocksPerGrid(ceil(numChars/1024.0));
		// Call RSA kernel
		cudaEventRecord(start);
		rsa<<<blocksPerGrid, 1024>>>(d_num, d_res, numChars);
		cudaEventRecord(stop);
		// Copy encrypted data back to host
		cudaMemcpy(gpu_array, d_res, numChars * sizeof(int), cudaMemcpyDeviceToHost);
		// Free memory
		cudaFree(d_num);
		cudaFree(d_res);
		cudaEventSynchronize(stop);
		float milliseconds = 0;
		cudaEventElapsedTime(&milliseconds, start, stop);
		printf("\nGPU Encryption Ellapsed Time: %f\n", milliseconds);

		// GPU Decryption
		cudaEventCreate(&start);
		cudaEventCreate(&stop);
		// Allocating GPU memory
		cudaMalloc((void **) &d_num, numChars * sizeof(int));
		cudaMalloc((void **) &d_res, numChars * sizeof(int));
		// Copy data to GPU
		cudaMemcpy(d_num, gpu_array, numChars * sizeof(int), cudaMemcpyHostToDevice);
		cudaMemcpyToSymbol(const_key, &d, sizeof(long));
		// Call RSA kernel
		cudaEventRecord(start);
		rsa<<<blocksPerGrid, 1024>>>(d_num, d_res, numChars);
		cudaEventRecord(stop);
		// Copy encrypted data back to host
		cudaMemcpy(gpu_array, d_res, numChars * sizeof(int), cudaMemcpyDeviceToHost);
		// Free memory
		cudaFree(d_num);
		cudaFree(d_res);
		cudaEventSynchronize(stop);
		milliseconds = 0;
		cudaEventElapsedTime(&milliseconds, start, stop);
		printf("GPU Decryption Ellapsed Time: %f\n", milliseconds);

		// Create decrypted file
		fp = fopen("decrypted_gpu.txt", "wb");
		for (int k = 0; k < numChars; k++) {
			fprintf(fp, "%c", gpu_array[k]+96);
		}
		fprintf(fp, "\n");
		fclose(fp);

		return 0;
	}
}