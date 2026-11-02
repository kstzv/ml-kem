/*
 * FreeRTOS V202212.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * https://www.FreeRTOS.org
 * https://github.com/FreeRTOS
 *
 */


/******************************************************************************
 * See https://www.freertos.org/freertos-on-qemu-mps2-an385-model.html for
 * instructions.
 *
 * This project provides two demo applications.  A simple blinky style project,
 * and a more comprehensive test and demo application.  The
 * mainCREATE_SIMPLE_BLINKY_DEMO_ONLY constant, defined in this file, is used to
 * select between the two.  The simply blinky demo is implemented and described
 * in main_blinky.c.  The more comprehensive test and demo application is
 * implemented and described in main_full.c.
 *
 * This file implements the code that is not demo specific, including the
 * hardware setup and FreeRTOS hook functions.
 *
 * Running in QEMU:
 * Use the following commands to start the application running in a way that
 * enables the debugger to connect, omit the "-s -S" to run the project without
 * the debugger:
 * qemu-system-arm -machine mps2-an385 -cpu cortex-m3 -kernel [path-to]/RTOSDemo.out -monitor none -nographic -serial stdio -s -S
 */

/* FreeRTOS includes. */
#include "FreeRTOS.h"
#include "task.h"

/* Standard includes. */
#include <stdio.h>
#include <string.h>

/* TODO: Steps for adding TraceRecorder are tagged with comments like this. */
/* TODO: This way, Eclipse IDEs can provide a summary in the Tasks window. */
/* TODO: To open Tasks, select Window -> Show View -> Tasks (or Other) */

/* TODO TraceRecorder (Step 1): Include trcRecorder.h to access the API. */
#include <trcRecorder.h>

/* This project provides two demo applications.  A simple blinky style demo
 * application, and a more comprehensive test and demo application.  The
 * mainCREATE_SIMPLE_BLINKY_DEMO_ONLY setting is used to select between the two.
 *
 * If mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is 1 then the blinky demo will be built.
 * The blinky demo is implemented and described in main_blinky.c.
 *
 * If mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is not 1 then the comprehensive test and
 * demo application will be built.  The comprehensive test and demo application is
 * implemented and described in main_full.c. */
#define mainCREATE_SIMPLE_BLINKY_DEMO_ONLY    1

/* printf() output uses the UART.  These constants define the addresses of the
 * required UART registers. */
#define UART0_ADDRESS                         ( 0x40004000UL )
#define UART0_DATA                            ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 0UL ) ) ) )
#define UART0_STATE                           ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 4UL ) ) ) )
#define UART0_CTRL                            ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 8UL ) ) ) )
#define UART0_BAUDDIV                         ( *( ( ( volatile uint32_t * ) ( UART0_ADDRESS + 16UL ) ) ) )
#define TX_BUFFER_MASK                        ( 1UL )

/*
 * main_blinky() is used when mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is set to 1.
 * main_full() is used when mainCREATE_SIMPLE_BLINKY_DEMO_ONLY is set to 0.
 */
extern void main_blinky( void );
extern void main_full( void );

/*
 * Only the comprehensive demo uses application hook (callback) functions.  See
 * https://www.FreeRTOS.org/a00016.html for more information.
 */
void vFullDemoTickHookFunction( void );
void vFullDemoIdleFunction( void );

/*
 * Printf() output is sent to the serial port.  Initialise the serial hardware.
 */
static void prvUARTInit( void );

/*-----------------------------------------------------------*/
// Header for ML-KEM prototype function
#include "ml_kem.h"
static void ml_kem_test_task(void *argument);

// Pseudo. Entropy generation for testing. This function is created only for testing
// For practical use you should use a reliable source of entropy 
// It is strictly NOT recommended to use this function in practice
static int test_entropy(void *buf, size_t len)
{
    static uint32_t state = 0x6d2b79f5u;
    uint8_t *output = (uint8_t *)buf;

    if (buf == NULL)
    {
        return -1;
    }

    for (size_t i = 0; i < len; i++)
    {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;

        output[i] = (uint8_t)state;
    }

    return 0;
}

#define TEST_STACK_DEPTH 512 // Cortex-M3: 512 StackType_t words = 2048 bytes

int main( void )
{
    /* See https://www.freertos.org/freertos-on-qemu-mps2-an385-model.html for
     * instructions. */

	/* Initializing TraceRecorder. Using #if (configUSE_TRACE_FACILITY == 1)
	 * is normally not needed. TraceRecorder API calls are normally ignored
     * and produce no code when configUSE_TRACE_FACILITY is 0, assuming 
	 * trcRecorder.h is included. However, this was missing for 
	 * xTraceTimestampSetPeriod() in TraceRecorder v4.10.2. */   
#if (configUSE_TRACE_FACILITY == 1)

	/* TODO TraceRecorder (Step 2): Call xTraceInitialize early in main().
	 * This should be called before any FreeRTOS calls are made. */
	xTraceInitialize();
	
	/* TODO TraceRecorder (Step 3): Call xTraceEnable to start tracing. */
	xTraceEnable(TRC_START);
	
	/* Extra step needed for using TraceRecorder on QEMU. */
	xTraceTimestampSetPeriod(configCPU_CLOCK_HZ/configTICK_RATE_HZ);

#endif	

    /* Hardware initialisation.  printf() output uses the UART for IO. */
    prvUARTInit();

	// ML-KEM port API test
    BaseType_t result = xTaskCreate(ml_kem_test_task, "ML-KEM", TEST_STACK_DEPTH, NULL, tskIDLE_PRIORITY + 1, NULL);
    if(result != pdPASS) { printf("Failed to create ML-KEM task\r\n"); for (;;) {} }
    vTaskStartScheduler();
    for (;;) {}
    return 0;
}
/*-----------------------------------------------------------*/

// Test ML-KEM key generation, encapsulation, and decapsulation in QEMU.
// WARNING: test_entropy() is deterministic and MUST NOT be used in production.
static void ml_kem_test_task(void *argument)
{
    (void)argument;

    static const struct {
        enum ml_kem_k level;
        size_t size_pk;
        size_t size_ct;
        const char *name;
    } test_cases[] = {
        { ML_KEM_512,  RES_PUBL_PART_LVL_512,  LEN_CIPHERTEXT_512,  "ML-KEM-512"  },
        { ML_KEM_768,  RES_PUBL_PART_LVL_768,  LEN_CIPHERTEXT_768,  "ML-KEM-768"  },
        { ML_KEM_1024, RES_PUBL_PART_LVL_1024, LEN_CIPHERTEXT_1024, "ML-KEM-1024" }
    };

    const size_t number_iterations = 1000;
    const size_t number_decaps_slots = 1;

    // Test one parameter set at a time to limit the peak FreeRTOS heap usage.
    for (size_t level_index = 0; level_index < sizeof(test_cases) / sizeof(test_cases[0]); ++level_index)
    {
        const enum ml_kem_k level = test_cases[level_index].level;
        const size_t size_pk = test_cases[level_index].size_pk;
        const size_t size_ct = test_cases[level_index].size_ct;
        const char *name = test_cases[level_index].name;

        // One reusable encapsulation slot for this parameter set.
        // Other subpools are disabled (slot count 0).
        struct ml_kem_pool_encaps_ctx *encaps_pool = create_encaps_pool(level == ML_KEM_512  ? 1 : 0, level == ML_KEM_768  ? 1 : 0, level == ML_KEM_1024 ? 1 : 0);
        if (encaps_pool == NULL)
        {
            printf("FAIL %s: create_encaps_pool()\r\n", name);
            goto test_failed;
        }

        printf("Testing %s: %u iterations\r\n", name, (unsigned int)number_iterations);

        for (size_t i = 0; i < number_iterations; ++i)
        {
            uint8_t *pk = NULL;
            uint8_t *ct = NULL;
            struct ml_kem_general_keys_decaps_ctx *decaps_ctx = NULL;
            uint8_t ss_encaps[ML_KEM_SEED_BYTES] = { 0 };
            uint8_t ss_decaps[ML_KEM_SEED_BYTES] = { 0 };
            const char *failed_step = NULL;
            int ret = 0;

            do
            {
                pk = pvPortMalloc(size_pk);
                if (pk == NULL) { failed_step = "pvPortMalloc(pk)"; break; }

                ct = pvPortMalloc(size_ct);
                if (ct == NULL) { failed_step = "pvPortMalloc(ct)"; break; }

                decaps_ctx = ml_kem_create_object(level, number_decaps_slots, test_entropy);
                if (decaps_ctx == NULL) { failed_step = "ml_kem_create_object"; break; }

                ret = ml_kem_get_public_key(decaps_ctx, pk, size_pk);
                if (ret != 0) { failed_step = "ml_kem_get_public_key"; break; }

                // Alternate between reusable-pool and temporary-context modes.
                // This verifies both branches of the new encapsulation API.
                struct ml_kem_pool_encaps_ctx *active_pool =
                    ((i & 1u) == 0u) ? encaps_pool : NULL;

                ret = ml_kem_encaps_core(active_pool,
                                          pk, size_pk, ct, size_ct,
                                          ss_encaps, sizeof(ss_encaps),
                                          test_entropy);
                if (ret != 0) { failed_step = "ml_kem_encaps_core"; break; }

                ret = ml_kem_decaps_core(decaps_ctx,
                                          ct, size_ct,
                                          ss_decaps, sizeof(ss_decaps));
                if (ret != 0) { failed_step = "ml_kem_decaps_core"; break; }

                if (memcmp(ss_encaps, ss_decaps, ML_KEM_SEED_BYTES) != 0)
                {
                    failed_step = "shared secrets differ";
                    break;
                }
            }
            while (0);

            if (failed_step != NULL)
            {
                if (ret != 0)
                {
                    printf("FAIL %s, iteration %u: %s (ret=%d)\r\n",
                           name, (unsigned int)(i + 1), failed_step, ret);
                }
                else
                {
                    printf("FAIL %s, iteration %u: %s\r\n",
                           name, (unsigned int)(i + 1), failed_step);
                }
            }

            // Clean up on every path (success and failure).
            ml_kem_memzero(ss_encaps, sizeof(ss_encaps));
            ml_kem_memzero(ss_decaps, sizeof(ss_decaps));
            ml_kem_destroy_core(decaps_ctx);  // Safe with NULL.
            vPortFree(ct);
            vPortFree(pk);

            if (failed_step != NULL)
            {
                ml_kem_encaps_pool_destroy(encaps_pool);
                goto test_failed;
            }

            if ((i + 1) % 100 == 0)
            {
                printf("%s: %u/%u OK\r\n", name,
                       (unsigned int)(i + 1), (unsigned int)number_iterations);
            }
        }

        ml_kem_encaps_pool_destroy(encaps_pool);
        printf("PASS %s\r\n", name);
    }

    printf("PASS: all ML-KEM parameter sets and both encapsulation modes\r\n");
    goto test_finished;

test_failed:
    printf("FAIL: ML-KEM QEMU reference test aborted\r\n");

test_finished:
    // Leave the test task alive and idle so serial output remains visible.
    for (;;)
    {
        vTaskDelay(portMAX_DELAY);
    }
}

void vApplicationMallocFailedHook( void )
{
    /* vApplicationMallocFailedHook() will only be called if
     * configUSE_MALLOC_FAILED_HOOK is set to 1 in FreeRTOSConfig.h.  It is a hook
     * function that will get called if a call to pvPortMalloc() fails.
     * pvPortMalloc() is called internally by the kernel whenever a task, queue,
     * timer or semaphore is created using the dynamic allocation (as opposed to
     * static allocation) option.  It is also called by various parts of the
     * demo application.  If heap_1.c, heap_2.c or heap_4.c is being used, then the
     * size of the	heap available to pvPortMalloc() is defined by
     * configTOTAL_HEAP_SIZE in FreeRTOSConfig.h, and the xPortGetFreeHeapSize()
     * API function can be used to query the size of free heap space that remains
     * (although it does not provide information on how the remaining heap might be
     * fragmented).  See http://www.freertos.org/a00111.html for more
     * information. */
    printf( "\r\n\r\nMalloc failed\r\n" );
    portDISABLE_INTERRUPTS();

    for( ; ; )
    {
    }
}
/*-----------------------------------------------------------*/

void vApplicationIdleHook( void )
{
    /* vApplicationIdleHook() will only be called if configUSE_IDLE_HOOK is set
     * to 1 in FreeRTOSConfig.h.  It will be called on each iteration of the idle
     * task.  It is essential that code added to this hook function never attempts
     * to block in any way (for example, call xQueueReceive() with a block time
     * specified, or call vTaskDelay()).  If application tasks make use of the
     * vTaskDelete() API function to delete themselves then it is also important
     * that vApplicationIdleHook() is permitted to return to its calling function,
     * because it is the responsibility of the idle task to clean up memory
     * allocated by the kernel to any task that has since deleted itself. */
}
/*-----------------------------------------------------------*/

void vApplicationStackOverflowHook( TaskHandle_t pxTask,
                                    char * pcTaskName )
{
    ( void ) pcTaskName;
    ( void ) pxTask;

    /* Run time stack overflow checking is performed if
     * configCHECK_FOR_STACK_OVERFLOW is defined to 1 or 2.  This hook
     * function is called if a stack overflow is detected. */
    printf( "\r\n\r\nStack overflow in %s\r\n", pcTaskName );
    portDISABLE_INTERRUPTS();

    for( ; ; )
    {
    }
}
/*-----------------------------------------------------------*/

void vApplicationTickHook( void )
{
    /* This function will be called by each tick interrupt if
    * configUSE_TICK_HOOK is set to 1 in FreeRTOSConfig.h.  User code can be
    * added here, but the tick hook is called from an interrupt context, so
    * code must not attempt to block, and only the interrupt safe FreeRTOS API
    * functions can be used (those that end in FromISR()). */

    #if ( mainCREATE_SIMPLE_BLINKY_DEMO_ONLY != 1 )
    {
        vFullDemoTickHookFunction();
    }
    #endif /* mainCREATE_SIMPLE_BLINKY_DEMO_ONLY */
}
/*-----------------------------------------------------------*/

void vApplicationDaemonTaskStartupHook( void )
{
    /* This function will be called once only, when the daemon task starts to
     * execute (sometimes called the timer task).  This is useful if the
     * application includes initialisation code that would benefit from executing
     * after the scheduler has been started. */
	 
	 xTraceEnable(TRC_START);
}
/*-----------------------------------------------------------*/

void vAssertCalled( const char * pcFileName,
                    uint32_t ulLine )
{
    volatile uint32_t ulSetToNonZeroInDebuggerToContinue = 0;

    /* Called if an assertion passed to configASSERT() fails.  See
     * http://www.freertos.org/a00110.html#configASSERT for more information. */

    printf( "ASSERT! Line %d, file %s\r\n", ( int ) ulLine, pcFileName );

    taskENTER_CRITICAL();
    {
        /* You can step out of this function to debug the assertion by using
         * the debugger to set ulSetToNonZeroInDebuggerToContinue to a non-zero
         * value. */
        while( ulSetToNonZeroInDebuggerToContinue == 0 )
        {
            __asm volatile ( "NOP" );
            __asm volatile ( "NOP" );
        }
    }
    taskEXIT_CRITICAL();
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION is set to 1, so the application must provide an
 * implementation of vApplicationGetIdleTaskMemory() to provide the memory that is
 * used by the Idle task. */
void vApplicationGetIdleTaskMemory( StaticTask_t ** ppxIdleTaskTCBBuffer,
                                    StackType_t ** ppxIdleTaskStackBuffer,
                                    uint32_t * pulIdleTaskStackSize )
{
/* If the buffers to be provided to the Idle task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xIdleTaskTCB;
    static StackType_t uxIdleTaskStack[ configMINIMAL_STACK_SIZE ];

    /* Pass out a pointer to the StaticTask_t structure in which the Idle task's
     * state will be stored. */
    *ppxIdleTaskTCBBuffer = &xIdleTaskTCB;

    /* Pass out the array that will be used as the Idle task's stack. */
    *ppxIdleTaskStackBuffer = uxIdleTaskStack;

    /* Pass out the size of the array pointed to by *ppxIdleTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulIdleTaskStackSize = configMINIMAL_STACK_SIZE;
}
/*-----------------------------------------------------------*/

/* configUSE_STATIC_ALLOCATION and configUSE_TIMERS are both set to 1, so the
 * application must provide an implementation of vApplicationGetTimerTaskMemory()
 * to provide the memory that is used by the Timer service task. */
void vApplicationGetTimerTaskMemory( StaticTask_t ** ppxTimerTaskTCBBuffer,
                                     StackType_t ** ppxTimerTaskStackBuffer,
                                     uint32_t * pulTimerTaskStackSize )
{
/* If the buffers to be provided to the Timer task are declared inside this
 * function then they must be declared static - otherwise they will be allocated on
 * the stack and so not exists after this function exits. */
    static StaticTask_t xTimerTaskTCB;
    static StackType_t uxTimerTaskStack[ configTIMER_TASK_STACK_DEPTH ];

    /* Pass out a pointer to the StaticTask_t structure in which the Timer
     * task's state will be stored. */
    *ppxTimerTaskTCBBuffer = &xTimerTaskTCB;

    /* Pass out the array that will be used as the Timer task's stack. */
    *ppxTimerTaskStackBuffer = uxTimerTaskStack;

    /* Pass out the size of the array pointed to by *ppxTimerTaskStackBuffer.
     * Note that, as the array is necessarily of type StackType_t,
     * configMINIMAL_STACK_SIZE is specified in words, not bytes. */
    *pulTimerTaskStackSize = configTIMER_TASK_STACK_DEPTH;
}
/*-----------------------------------------------------------*/

static void prvUARTInit( void )
{
    UART0_BAUDDIV = 16;
    UART0_CTRL = 1;
}
/*-----------------------------------------------------------*/

#ifdef __PICOLIBC__
int
_uart_putc(char c, FILE *file)
{
    ( void ) file;

    while( ( UART0_STATE & TX_BUFFER_MASK ) != 0 )
    {
    }

    UART0_DATA = c;
    return (unsigned char) c;
}

static FILE __stdio = FDEV_SETUP_STREAM(_uart_putc, NULL, NULL, _FDEV_SETUP_WRITE);
__attribute__( ( used ) ) FILE *const stdout = &__stdio;
#else
/*-----------------------------------------------------------*/

int __write( int iFile,
             char * pcString,
             int iStringLength )
{
    int iNextChar;

    /* Avoid compiler warnings about unused parameters. */
    ( void ) iFile;

    /* Output the formatted string to the UART. */
    for( iNextChar = 0; iNextChar < iStringLength; iNextChar++ )
    {
        while( ( UART0_STATE & TX_BUFFER_MASK ) != 0 )
        {
        }

        UART0_DATA = *pcString;
        pcString++;
    }

    return iStringLength;
}
/*-----------------------------------------------------------*/

void * malloc( size_t size )
{
    ( void ) size;

    /* This project uses heap_4 so doesn't set up a heap for use by the C
     * library - but something is calling the C library malloc().  See
     * https://freertos.org/a00111.html for more information. */
    printf( "\r\n\r\nUnexpected call to malloc() - should be usine pvPortMalloc()\r\n" );
    portDISABLE_INTERRUPTS();

    for( ; ; )
    {
    }
}
#endif
