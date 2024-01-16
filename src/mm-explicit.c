/*
 * mm-implicit.c - The best malloc package EVAR!
 *
 * TODO (bug): mm_realloc and mm_calloc don't seem to be working...
 * TODO (bug): The allocator doesn't re-use space very well...
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memlib.h"
#include "mm.h"

/** The required alignment of heap payloads */
const size_t ALIGNMENT = 2 * sizeof(size_t);

/** The layout of each block allocated on the heap */
typedef struct {
    /** The size of the block and whether it is allocated (stored in the low bit) */
    size_t header;
    /**
     * We don't know what the size of the payload will be, so we will
     * declare it as a zero-length array.  This allow us to obtain a
     * pointer to the start of the payload.
     */
    uint8_t payload[];
} block_t;

// typedef struct {
//     size_t foot;
// } footer_t;

typedef struct free_block {
    size_t header;
    struct free_block *prev;
    struct free_block *next;
} free_block_t;

/** The first and last blocks on the heap */
static block_t *mm_heap_first = NULL;
static block_t *mm_heap_last = NULL;
static free_block_t *free_tail = NULL;

/** Rounds up `size` to the nearest multiple of `n` */
static size_t round_up(size_t size, size_t n) {
    return (size + (n - 1)) / n * n;
}

/** Set's a block's header with the given size and allocation state */
static void set_header(block_t *block, size_t size, bool is_allocated) {
    block->header = size | is_allocated;
}

static void set_footer(block_t *block, size_t size, bool is_allocated) {
    size_t *footer_loc = (void *) block + size - sizeof(size_t);
    *footer_loc = size | is_allocated;
}

/** Extracts a block's size from its header */
static size_t get_size(block_t *block) {
    return block->header & ~1;
}

/** Extracts a block's allocation state from its header */
static bool is_allocated(block_t *block) {
    return block->header & 1;
}

// write a function that directly adds a block to the free list
// and removes block from free list

static void free_list_add(free_block_t *block) {
    if (free_tail == NULL) {
        block->prev = NULL;
        block->next = NULL;
        free_tail = block;
    }
    else {
        // free_block_t *temp  = free_tail;
        // free_tail = block;
        // free_tail->prev = temp;
        // temp->next = free_tail;
        // free_tail->next = NULL;
        free_tail->next = block;
        block->prev = free_tail;
        block->next = NULL;
        free_tail = block;
    }
}
// block1 block2 blocklast
// block1 curr block2
// curr block1 block2

static void free_list_remove(free_block_t *block) {
    if (block == free_tail && free_tail->prev == NULL) {
        free_tail = NULL;
    }
    else if (block == free_tail && free_tail->prev != NULL) {
        free_tail = block->prev;
        free_tail->next = NULL;
    }
    else if (block->prev == NULL) {
        block->next->prev = NULL;
    }
    else { // error fires when block->next is null (but somehow block is not free_tail)
        if (block->prev != NULL) {
            block->prev->next = block->next;
        }
        if (block->next != NULL) {
            block->next->prev = block->prev;
        }
        // block->prev->next = block->next;
        // block->next->prev = block->prev;
    }
}

static void splice_two(block_t *left_mem, block_t *right_mem) {
    if (!is_allocated(left_mem) && !is_allocated(right_mem)) {
        set_footer(left_mem, get_size(left_mem) + get_size(right_mem), false);
        set_header(left_mem, get_size(left_mem) + get_size(right_mem), false);
        free_list_remove(
            (free_block_t *) right_mem); // error from next_mem (curr < mm_heap_last)
        if (mm_heap_last == right_mem) {
            mm_heap_last = left_mem;
        }
        // if (free_tail == (free_block_t *) right_mem) {
        //     free_tail = (free_block_t *) left_mem;
        // }
    }
}

static void coalesce(block_t *curr) {
    if (mm_heap_last == mm_heap_first) {
        return;
    }
    if (curr < mm_heap_last) { // if i comment this if out, i terminate with 3 errors
        block_t *next_mem = (void *) curr + get_size(curr);
        splice_two(curr, next_mem);
    }
    if (curr > mm_heap_first) {
        // size_t *prev_mem_foot = (void *) curr - sizeof(size_t);
        // block_t *prev_mem = (void *) curr - (*prev_mem_foot & ~1);
        block_t *prev_mem_foot = (void *) curr - sizeof(size_t);
        block_t *prev_mem = (void *) curr - get_size(prev_mem_foot);
        splice_two(prev_mem, curr);
    }
}

/**
 * Finds the first free block in the heap with at least the given size.
 * If no block is large enough, returns NULL.
 */
static free_block_t *find_fit(size_t size) {
    // Traverse the blocks in the heap using the implicit list
    for (free_block_t *curr = free_tail; curr != NULL; curr = curr->prev) {
        // If the block is free and large enough for the allocation, return it
        if (get_size((block_t *) curr) >= size) {
            return curr;
        }
    }
    return NULL;
}

/** Gets the header corresponding to a given payload pointer */
static block_t *block_from_payload(void *ptr) {
    return ptr - offsetof(block_t, payload);
}

/**
 * mm_init - Initializes the allocator state
 */
bool mm_init(void) {
    // We want the first payload to start at ALIGNMENT bytes from the start of the heap
    void *padding = mem_sbrk(ALIGNMENT - sizeof(block_t));
    if (padding == (void *) -1) {
        return false;
    }

    // Initialize the heap with no blocks
    mm_heap_first = NULL;
    mm_heap_last = NULL;
    free_tail = NULL;
    return true;
}

/**
 * mm_malloc - Allocates a block with the given size
 */
void *mm_malloc(size_t size) {
    // The block must have enough space for a header and be 16-byte aligned
    if (size < (2 * sizeof(size_t))) {
        size = 2 * sizeof(size_t);
    }
    size = round_up(sizeof(block_t) + size + sizeof(size_t), ALIGNMENT);

    // If there is a large enough free block, use it
    block_t *block = (block_t *) find_fit(size);
    if (block != NULL) {
        if (get_size(block) >= size + (sizeof(size_t) + sizeof(free_block_t))) {
            free_block_t *free_block = (void *) block + size;

            // set_header(block, size, true);
            // set_footer(block, size, true);

            set_header((block_t *) free_block, get_size(block) - size, false);
            set_footer((block_t *) free_block, get_size(block) - size, false);
            free_list_add(free_block);

            if (block == mm_heap_last) {
                mm_heap_last = (block_t *) free_block;
            }

            free_list_remove((free_block_t *) block);

            set_header(block, size, true);
            set_footer(block, size, true);

            return block->payload;
        }
        else {
            free_list_remove((free_block_t *) block);

            set_header(block, get_size(block), true);
            set_footer(block, get_size(block), true);

            return block->payload;
        }
    }

    // Otherwise, a new block needs to be allocated at the end of the heap
    block = mem_sbrk(size);
    if (block == (void *) -1) {
        return NULL;
    }

    // Update mm_heap_first and mm_heap_last since we extended the heap
    if (mm_heap_first == NULL) {
        mm_heap_first = block;
    }
    mm_heap_last = block;

    // Initialize the block with the allocated size
    set_header(block, size, true);
    set_footer(block, size, true);

    return block->payload;
}

/**
 * mm_free - Releases a block to be reused for future allocations
 */
void mm_free(void *ptr) {
    // mm_free(NULL) does nothing
    if (ptr == NULL) {
        return;
    }

    // Mark the block as unallocated
    block_t *block = block_from_payload(ptr);
    set_header(block, get_size(block), false);
    set_footer(block, get_size(block), false);

    free_list_add((free_block_t *) block);
    coalesce(block);
}

/**
 * mm_realloc - Change the size of the block by mm_mallocing a new block,
 *      copying its data, and mm_freeing the old block.
 */
void *mm_realloc(void *old_ptr, size_t size) {
    if (old_ptr == NULL) {
        return mm_malloc(size);
    }

    if (size == 0) {
        mm_free(old_ptr);
        return NULL;
    }

    block_t *new_block = block_from_payload(mm_malloc(size));
    block_t *old_block = block_from_payload(old_ptr);

    size_t bytes_to_copy = size;
    if (size > get_size(old_block) - (2 * sizeof(size_t))) {
        bytes_to_copy = get_size(old_block) - (2 * sizeof(size_t));
    }
    memcpy(new_block->payload, old_block->payload, bytes_to_copy);

    mm_free(old_block->payload);

    return new_block->payload;
}

/**
 * mm_calloc - Allocate the block and set it to zero.
 */
void *mm_calloc(size_t nmemb, size_t size) {
    block_t *block = block_from_payload(mm_malloc(nmemb * size));
    memset(block->payload, 0, nmemb);

    return block->payload;
}

/**
 * mm_checkheap - So simple, it doesn't need a checker!
 */
void mm_checkheap(void) {
    size_t heap_free_count = 0;
    for (block_t *curr = mm_heap_first; mm_heap_last != NULL && curr <= mm_heap_last;
         curr = (void *) curr + get_size(curr)) {
        // if (get_size(curr) != get_size_footer(curr) ||
        //     is_allocated(curr) != is_allocated_footer(curr)) {
        //     fprintf(stderr, "header != footer\n");
        // }

        if (!is_allocated(curr)) {
            heap_free_count++;
        }
    }

    if (free_tail == NULL) {
        return;
    }

    size_t free_list_count = 0;
    for (free_block_t *curr = free_tail; curr != NULL; curr = curr->prev) {
        // if (is_allocated((block_t *) curr) || is_allocated_footer((block_t *) curr)) {
        //     fprintf(stderr, "block should not be in free list\n");
        // }
        free_list_count++;
    }

    fprintf(stderr, "no. of free blocks in heap: %ld\n", heap_free_count);
    fprintf(stderr, "no. of blocks in free list: %ld\n", free_list_count);
}
