#include <stdio.h>
#include "board.h"
#include "peripherals.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "MK82F25615.h"
#include "fsl_debug_console.h"
#include "fsl_trng.h"

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfcrypt/test/test.h>
#include <wolfcrypt/benchmark/benchmark.h>

/*****************************************************************************
 * Private types/enumerations/variables
 ****************************************************************************/



static void hw_rand_init(void)
{
#ifdef FREESCALE_KSDK_BM
    trng_config_t trngConfig;
    TRNG_GetDefaultConfig(&trngConfig);
    /* Set sample mode of the TRNG ring oscillator to Von Neumann, for better random data */
    trngConfig.sampleMode = kTRNG_SampleModeVonNeumann;
    /* Initialize TRNG */
    TRNG_Init(TRNG0, &trngConfig);
#else
    /* Enable RNG clocks */
    SIM->SCGC6 |= SIM_SCGC6_RNGA_MASK;
    SIM->SCGC3 |= SIM_SCGC3_RNGA_MASK;

    /* Wake up RNG to normal mode (take out of sleep) */
    RNG->CR &= ~RNG_CR_SLP_MASK;

    /* Enable High Assurance mode (Enables notification of security violations via SR[SECV]) */
    RNG->CR |= RNG_CR_HA_MASK;

    /* Enable RNG generation to RANDOUT FIFO */
    RNG->CR |= RNG_CR_GO_MASK;
#endif
}


/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;

const char menu1[] = "\r\n"
    "\tt. WolfSSL Test\r\n"
    "\tb. WolfSSL Benchmark\r\n";

/*****************************************************************************
 * Private functions
 ****************************************************************************/

/*****************************************************************************
 * Public functions
 ****************************************************************************/
int main(void)
{
    int opt = 0;
    func_args args;

    /* Init board hardware. */
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitBootPeripherals();
    hw_rand_init();
#ifndef BOARD_INIT_DEBUG_CONSOLE_PERIPHERAL
    /* Init FSL debug console. */
    BOARD_InitDebugConsole();
#endif

    wolfCrypt_Init(); /* calls LTC_Init() */

    while (1) {
    	printf("\r\n\t\t\t\tMENU\r\n");
    	printf(menu1);
    	printf("Please select one of the above options: ");

        opt = 0;
        while (opt == 0) {
        	opt = getchar();
        }

        switch (opt) {

        case 't':
            memset(&args, 0, sizeof(args));
            printf("\nCrypt Test\n");
#ifndef NO_CRYPT_TEST
            wolfcrypt_test(&args);
#else
            args.return_code = NOT_COMPILED_IN;
#endif
            printf("Crypt Test: Return code %d\n", args.return_code);
            break;

        case 'b':
            memset(&args, 0, sizeof(args));
            printf("\nBenchmark Test\n");
#ifndef NO_CRYPT_BENCHMARK
            benchmark_test(&args);
#else
            args.return_code = NOT_COMPILED_IN;
#endif
            printf("Benchmark Test: Return code %d\n", args.return_code);
            break;

        // All other cases go here
        default:
        	printf("\r\nSelection out of range\r\n");
        	break;
        }
    }

    wolfCrypt_Cleanup();
}
