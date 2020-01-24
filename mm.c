#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.
 * When you hand in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
#define debug(fmt, ...) printf("%s: " fmt "\n", __func__, __VA_ARGS__)
#define msg(...) printf(__VA_ARGS__)
#else
#define debug(fmt, ...)
#define msg(...)
#endif

#define __unused __attribute__((unused))

/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* !DRIVER */

typedef int32_t word_t; /* Heap is bascially an array of 4-byte words. */

typedef enum
{
  FREE = 0,     /* Block is free */
  USED = 1,     /* Block is used */
  PREVFREE = 2, /* Previous block is free (optimized boundary tags) */
} bt_flags;

static word_t *heap_zero;  /* Address of the first byte ever returned from mem_sbrk() */
static word_t *heap_start; /* Address of the first block */
static word_t *heap_end;   /* Address past last byte of last block */
static word_t *last;       /* Points at last block */

//wersja bez kubelkow!!!!!!!!!
//static word_t *list_start; /* Address of the first free block */
//static word_t *list_last;  /* Address of the last free block */

static word_t *free_lists;
static const int maxindex = 258;

/* --=[ boundary tag handling ]=-------------------------------------------- */

static inline word_t bt_size(word_t *bt)
{
  return *bt & ~(USED | PREVFREE);
}

static inline int bt_used(word_t *bt)
{
  return *bt & USED;
}

static inline int bt_free(word_t *bt)
{
  return !(*bt & USED);
}

/* Given boundary tag address calculate it's buddy address. */
static inline word_t *bt_footer(word_t *bt)
{
  return (void *)bt + bt_size(bt) - sizeof(word_t);
}

/* Given payload pointer returns an address of boundary tag. */
static inline word_t *bt_fromptr(void *ptr)
{
  return (word_t *)ptr - 1;
}

/* Creates boundary tag(s) for given block. */
/* Added functionality: Sets the prev and next offsets in a block if it is marked as free */
static inline void bt_make(word_t *bt, size_t size, bt_flags flags)
{
  (*bt) = size | flags;
  (*bt_footer(bt)) = size | flags;
}

/* Previous block free flag handling for optimized boundary tags. */
static inline bt_flags bt_get_prevfree(word_t *bt)
{
  return *bt & PREVFREE;
}

static inline void bt_clr_prevfree(word_t *bt)
{
  if (bt)
    *bt &= ~PREVFREE;
}

static inline void bt_set_prevfree(word_t *bt)
{
  *bt |= PREVFREE;
}

/* Returns address of payload. */
static inline void *bt_payload(word_t *bt)
{
  return bt + 1;
}

/* Returns address of next block or NULL. */
static inline word_t *bt_next(word_t *bt)
{
  if (bt == last)
    return NULL;
  return (void *)bt + bt_size(bt);
}

/* Returns address of previous block or NULL. */
static inline word_t *bt_prev(word_t *bt)
{
  if (heap_start == bt)
    return NULL;
  word_t *prevfooter = bt - 1;
  void *prevheader = (void *)prevfooter - bt_size(prevfooter) + sizeof(word_t);
  return prevheader;
}

/* Lists of free blocks aux functions */

//It returns an offset!!!
static inline word_t ls_prev(word_t *ptr)
{
  return *(ptr + 1);
}

//It returns an offset!!!
static inline word_t ls_next(word_t *ptr)
{
  return *(ptr + 2);
}

static inline void ls_set_prev(word_t *ptr, word_t offset)
{
  *(ptr + 1) = offset;
}

static inline void ls_set_next(word_t *ptr, word_t offset)
{
  *(ptr + 2) = offset;
}

static inline word_t *ls_addrfromoff(word_t offset)
{
  return (word_t *)((void *)heap_zero + (uint64_t)offset);
}

static inline word_t ls_offfromaddr(word_t *pointer)
{
  return (word_t)(uint64_t)((void *)pointer - (uint64_t)heap_zero);
}

static inline int ls_indexfromsize(size_t size)
{

  //exponential version

  /*
  size >>= 4;
  long long index;
  asm("bsr %1, %0\n"
      : "=r"(index)
      : "r"(size));
  if (size - ((long long)1 << index) != 0)
    index++;
  return index + 1 < maxindex ? index + 1 : maxindex;
  */

  //linear version

  int index = size >> 4;
  if (index >= maxindex)
    return maxindex;
  else
    return index;
}

static inline void ls_add(word_t *block)
{
  int index = ls_indexfromsize(bt_size(block));
  if (free_lists[index] == 0) //pusta lista
  {
    word_t block_offset = ls_offfromaddr(block);
    free_lists[index] = block_offset;
    ls_set_next(block, block_offset);
    ls_set_prev(block, block_offset);
  }
  else
  {
    word_t block_offset = ls_offfromaddr(block);
    word_t *first_elem = ls_addrfromoff(free_lists[index]);
    word_t *last_elem = ls_addrfromoff(ls_prev(first_elem));
    ls_set_next(block, free_lists[index]);
    ls_set_prev(block, ls_offfromaddr(last_elem));
    ls_set_next(last_elem, block_offset);
    ls_set_prev(first_elem, block_offset);
  }
}

static inline void ls_remove(word_t *block)
{
  int index = ls_indexfromsize(bt_size(block));
  word_t *first_elem = ls_addrfromoff(free_lists[index]);
  word_t *last_elem = ls_addrfromoff(ls_prev(first_elem));
  if (block == first_elem && block == last_elem) // block jest jedynym blokiem na liscie
  {
    free_lists[index] = 0;
  }
  else
  {
    word_t prev_elem_offset = ls_prev(block);
    word_t *prev_elem = ls_addrfromoff(prev_elem_offset);
    word_t next_elem_offset = ls_next(block);
    word_t *next_elem = ls_addrfromoff(next_elem_offset);
    ls_set_next(prev_elem, next_elem_offset);
    ls_set_prev(next_elem, prev_elem_offset);
    if (block == first_elem)
      free_lists[index] = next_elem_offset;
  }
}

/* --=[ miscellanous procedures ]=------------------------------------------ */

/* Calculates block size incl. header, footer & payload,
 * and aligns it to block boundary (ALIGNMENT). */
static inline size_t blksz(size_t size)
{
  size_t payload_and_footer = size + sizeof(word_t);
  if (payload_and_footer % ALIGNMENT == 0)
    return payload_and_footer + ALIGNMENT; //header + payload + footer + padding (wielkosci aligmnent minus jedno slowo)
  else if (payload_and_footer % ALIGNMENT == ALIGNMENT - sizeof(word_t))
    return sizeof(word_t) + payload_and_footer; //header + payload + footer + padding
  else if (payload_and_footer % ALIGNMENT > ALIGNMENT - sizeof(word_t))
    return payload_and_footer + ALIGNMENT - payload_and_footer % ALIGNMENT + ALIGNMENT;
  else
    return sizeof(word_t) + payload_and_footer + ALIGNMENT - payload_and_footer % ALIGNMENT - sizeof(word_t);
}

static void *morecore(size_t size)
{
  void *ptr = mem_sbrk(size);
  if (ptr == (void *)-1)
    return NULL;
  return ptr;
}

/* --=[ mm_init ]=---------------------------------------------------------- */

int mm_init(void)
{
  void *ptr = morecore((maxindex + 1) * 4); //wczesniej bylo:   3 * ALIGNMENT - sizeof(word_t)
  if (!ptr)
    return -1;
  heap_start = NULL;
  heap_zero = memset(ptr, 0, (maxindex + 1) * 4);
  free_lists = heap_zero;
  heap_end = NULL;
  last = NULL;
  return 0;
}

/* --=[ malloc ]=----------------------------------------------------------- */

#if 1
/* First fit startegy. */
static word_t *find_fit(size_t reqsz) // reqsz to szukana wielkosc bloku, a nie payloadu
{
  int index = ls_indexfromsize(reqsz);
  while (index <= maxindex)
  {
    if (free_lists[index] == 0)
    {
      index++;
      continue;
    }
    word_t *first_elem = ls_addrfromoff(free_lists[index]);
    word_t *pointer = first_elem;
    do
      if (bt_size(pointer) >= reqsz)
        return pointer;
      else
        pointer = ls_addrfromoff(ls_next(pointer));
    while (pointer != first_elem);
    index++;
  }
  return NULL;
}
#else
/* Best fit startegy. */
static word_t *find_fit(size_t reqsz)
{
}
#endif

void *malloc(size_t size)
{

  //TODO: MONA OPTMALIZOWAC PRYPADKE ZE OSTATNI BLOK JEST PUSTY I ZA MALY

  //TODO: MOZNA BY ZROBIC OSOBNA LISTE NA MALE BLOKI NP DO 32B
  size_t blocksize = blksz(size);
  word_t *pointer = find_fit(blocksize);
  if (pointer == NULL)
  {
    if (heap_start && bt_free(last))
    { /*
      pointer = mem_sbrk(blocksize);
      heap_end = (void *)pointer + blocksize;
      bt_make(pointer, blocksize, USED);
      last = pointer;
      return bt_payload(pointer);*/

      ls_remove(last);
      mem_sbrk(blocksize - bt_size(last));
      heap_end = (void *)heap_end + blocksize - bt_size(last);
      bt_make(last, blocksize, USED);
      return bt_payload(last);
    }
    else
    {
      pointer = mem_sbrk(blocksize);
      if ((long)pointer < 0)
        return NULL;
      if (!heap_start)
        heap_start = pointer;
      last = pointer;
      heap_end = (void *)pointer + blocksize;
      bt_make(pointer, blocksize, USED);
    }
  }
  else // pointer!=NULL
  {
    size_t nonused_size = bt_size(pointer) - blocksize;
    if (nonused_size < ALIGNMENT)
    {
      ls_remove(pointer);
      bt_make(pointer, bt_size(pointer), USED);
    }
    else
    {
      ls_remove(pointer);
      bt_make(pointer, blocksize, USED);
      word_t *nonused_pointer = (void *)pointer + blocksize;
      bt_make(nonused_pointer, nonused_size, FREE);
      ls_add(nonused_pointer);
      if (last == pointer)
        last = nonused_pointer;
    }
  }
  return bt_payload(pointer);
}

/* --=[ free ]=------------------------------------------------------------- */

void free(void *ptr)
{
  if (ptr == NULL)
    return;
  word_t *header = bt_fromptr(ptr);
  if (bt_free(header))
    return;
  size_t new_size = bt_size(header);
  word_t *prev_header = bt_prev(header);
  word_t *next_header = bt_next(header);
  int next_is_free = next_header && bt_free(next_header);
  int prev_is_free = prev_header && bt_free(prev_header);
  if (next_is_free && prev_is_free)
  {
    if (next_header == last)
      last = prev_header;
    ls_remove(prev_header);
    ls_remove(next_header);
    new_size += bt_size(prev_header) + bt_size(next_header);
    bt_make(prev_header, new_size, FREE);
    ls_add(prev_header);
  }
  else if (next_is_free)
  {
    if (next_header == last)
      last = header;
    ls_remove(next_header);
    new_size += bt_size(next_header);
    bt_make(header, new_size, FREE);
    ls_add(header);
  }
  else if (prev_is_free)
  {
    if (header == last)
      last = prev_header;
    ls_remove(prev_header);
    new_size += bt_size(prev_header);
    bt_make(prev_header, new_size, FREE);
    ls_add(prev_header);
  }
  else //no adjacent free blocks
  {
    bt_make(header, new_size, FREE); // new_size to stara dlugosc w tym przypadku
    ls_add(header);
  }
  //msg("++++++++++++++++++++++EMERGENCY CHECKHEAP+++++++++++++++\n");
  //mm_checkheap(1);
  //msg("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}

/* --=[ realloc ]=---------------------------------------------------------- */

void *realloc(void *old_ptr, size_t size)
{
  if (old_ptr == NULL && size != 0)
    return malloc(size);

  if (old_ptr == NULL && size == 0)
    return NULL;

  if (old_ptr != NULL && size < ALIGNMENT)
  {
    free(old_ptr);
    return NULL;
  }

  word_t *boundary = bt_fromptr(old_ptr);
  word_t *next_boundary = bt_next(boundary);
  word_t *prev_boundary = bt_prev(boundary);
  size_t blocksize = blksz(size);
  if (blocksize > bt_size(boundary))
  {
    if (next_boundary && bt_free(next_boundary) && next_boundary == last && (size_t)bt_size(boundary) + (size_t)bt_size(next_boundary) < blocksize)
    {
      ls_remove(next_boundary);
      mem_sbrk(blocksize - (size_t)bt_size(boundary) - (size_t)bt_size(next_boundary));
      heap_end = (void *)heap_end + blocksize - (size_t)bt_size(boundary) - (size_t)bt_size(next_boundary);
      last = boundary;
      bt_make(boundary, blocksize, USED);
      return old_ptr;
    }
    else if (next_boundary && bt_free(next_boundary) && (size_t)bt_size(boundary) + (size_t)bt_size(next_boundary) >= blocksize)
    {
      size_t nonused_size = bt_size(boundary) + bt_size(next_boundary) - blocksize;
      if (nonused_size < ALIGNMENT)
      {
        if (last == next_boundary)
          last = boundary;
        ls_remove(next_boundary);
        bt_make(boundary, nonused_size + blocksize, USED);
      }
      else
      {
        ls_remove(next_boundary);
        bt_make(boundary, blocksize, USED);
        word_t *nonused_pointer = (void *)boundary + blocksize;
        bt_make(nonused_pointer, nonused_size, FREE);
        ls_add(nonused_pointer);
        if (last == next_boundary)
          last = nonused_pointer;
      }
      return old_ptr;
    }
    else if (next_boundary && prev_boundary && bt_free(next_boundary) && bt_free(prev_boundary) && (size_t)bt_size(boundary) + (size_t)bt_size(boundary) + (size_t)bt_size(next_boundary) >= blocksize)
    {
      size_t nonused_size = bt_size(prev_boundary) + bt_size(boundary) + bt_size(next_boundary) - blocksize;
      if (nonused_size < ALIGNMENT)
      {
        if (last == next_boundary)
          last = prev_boundary;
        ls_remove(prev_boundary);
        ls_remove(next_boundary);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize + nonused_size, USED);
      }
      else
      {
        word_t *nonused_pointer = (void *)prev_boundary + blocksize;
        ls_remove(prev_boundary);
        ls_remove(next_boundary);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize, USED);
        bt_make(nonused_pointer, nonused_size, FREE);
        ls_add(nonused_pointer);
        if (last == next_boundary)
          last = nonused_pointer;
      }
      return bt_payload(prev_boundary);
    }
    else if (prev_boundary && bt_free(prev_boundary) && (size_t)bt_size(prev_boundary) + (size_t)bt_size(boundary) >= blocksize)
    {
      size_t nonused_size = bt_size(prev_boundary) + bt_size(boundary) - blocksize;
      if (nonused_size < ALIGNMENT)
      {
        if (last == boundary)
          last = prev_boundary;
        ls_remove(prev_boundary);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize + nonused_size, USED);
      }
      else
      {
        word_t *nonused_pointer = (void *)prev_boundary + blocksize;
        ls_remove(prev_boundary);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize, USED);
        bt_make(nonused_pointer, nonused_size, FREE);
        ls_add(nonused_pointer);
        if (last == boundary)
          last = nonused_pointer;
      }
      return bt_payload(prev_boundary);
    }
    else
    {
      //TODO: MOZNA ZOPTYMALIZOWAC
      size_t newsize = (size > 2 * bt_size(boundary) - 4 * sizeof(word_t)) ? size : 2 * bt_size(boundary) - 4 * sizeof(word_t);
      void *new_ptr = malloc(newsize);
      if (!new_ptr)
        return NULL;
      memcpy(new_ptr, old_ptr, bt_size(boundary) - (sizeof(word_t) << 1));
      free(old_ptr);
      return new_ptr;
    }
  }
  else if (blocksize < bt_size(boundary)) // oraz oczywiscie blocksize >= ALIGNMENT
  {
    if (blocksize >= bt_size(boundary) / 2)
      return old_ptr;
    bt_make(boundary, blocksize, USED);
    if (next_boundary && bt_free(next_boundary))
    {
      if (last == next_boundary)
        last = boundary + blocksize;
      word_t *nonused_pointer = (void *)boundary + blocksize;
      bt_make(nonused_pointer, bt_size(boundary) + bt_size(next_boundary) - blocksize, FREE);
      ls_add(nonused_pointer);
    }
    else //zauwazmy, ze bt_size(boundary)-blocksize jest wielkosci co najmniej ALIGMENT, bo kazdy z nich jest wielokrotnoscia ALIGMENT
    {
      word_t *new_block = (void *)boundary + blocksize;
      if (last == boundary)
        last = new_block;
      bt_make(new_block, bt_size(boundary) - blocksize, FREE);
      ls_add(new_block);
    }
    return old_ptr;
  }
  else
    return old_ptr;
}

/* --=[ calloc ]=----------------------------------------------------------- */

void *calloc(size_t nmemb, size_t size)
{
  size_t bytes = nmemb * size;
  void *new_ptr = malloc(bytes);
  if (new_ptr)
    memset(new_ptr, 0, bytes);
  return new_ptr;
}

/* --=[ mm_checkheap ]=----------------------------------------------------- */

void mm_checkheap(int verbose)
{

  if (verbose)
  {
    msg("%d %d %d %ld", ls_indexfromsize(blksz(128)), ls_indexfromsize(blksz(112)), ls_indexfromsize(32), blksz(128));
    msg("HEAP STRUCTURE\n");
    msg("hs-he:%ld\n", (uint64_t)((void *)heap_start - (uint64_t)heap_zero));
    msg("last:%ld heap_end:%ld\nheap_zero:%ld\n", (void *)last - (void *)heap_start, (void *)heap_end - (void *)heap_start, (long int)heap_zero);
    int counter = 0;
    for (void *i = heap_start; i < (void *)heap_end; i += bt_size(i), counter++)
      msg("[%d] header:%d footer:%d size:%d isfree:%d isused:%d islast:%d, Bfirst:%ld,Blast:%ld,prev:%d,next:%d,index:%d\n", counter, (*(word_t *)i), (*bt_footer(i)), bt_size(i), bt_free(i), bt_used(i), last == (word_t *)i ? 1 : 0, i - (void *)heap_start, (void *)bt_footer(i) - (void *)heap_start, ls_prev(i), ls_next(i), ls_indexfromsize(bt_size(i)));
    msg("-------------------------------------------\n");
  }

  //wersja dla programu tylko z boundary tagami
  // verbose moze byc rowne 0,1,2
  void *prev_i = NULL;
  int counter = 0;
  for (void *i = heap_start; i < (void *)heap_end; i += bt_size(i))
  {
    if (bt_payload(i) >= (void *)heap_end)
      msg("[%d] CHECKHEAP ERROR: PAYLOAD OUTSIDE HEAP\n", counter);

    if (bt_footer(i) >= heap_end)
      msg("[%d] CHECKHEAP ERROR: FOOTER OUTSIDE HEAP\n", counter);

    if (bt_size(i) % 16)
      msg("[%d] CHECKHEAP ERROR: SIZE NOT DIVISIBLE BY 16\n", counter);

    if (prev_i && bt_free(prev_i) && bt_free(i))
      msg("[%d] [%d] CHECKHEAP ERROR: TWO FREE BLOCKS ADJACENT\n", counter - 1, counter);

    //trzeba jesxe srpawdac czy element jest free
    /*if (i == list_start && ls_prev(i) != 0)
      msg("[%d] CHECKHEAP ERROR: FIRST ELEMENT OF THE FREE LIST HAS NONZERO PREV\n", counter);

    if (i != list_start && ls_prev(i) == 0)
      msg("[%d] CHECKHEAP ERROR: NONFIRST ELEMENT OF THE FREE LIST HAS ZERO PREV\n", counter);

    if (i == list_last && ls_next(i) != 0)
      msg("[%d] CHECKHEAP ERROR: LAST ELEMENT OF THE FREE LIST HAS NONZERO NEXT\n", counter);

    if (i != list_last && ls_next(i) == 0)
      msg("[%d] CHECKHEAP ERROR: NONLAST ELEMENT OF THE FREE LIST HAS ZERO NEXT\n", counter);
      */
    prev_i = i;
    counter++;
  }
}
