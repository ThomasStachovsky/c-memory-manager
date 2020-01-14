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

static word_t *heap_start; /* Address of the first block */
static word_t *heap_end;   /* Address past last byte of last block */
static word_t *last;       /* Points at last block */

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
  void *ptr = morecore(ALIGNMENT - sizeof(word_t));
  if (!ptr)
    return -1;
  heap_start = NULL;
  heap_end = NULL;
  last = NULL;
  return 0;
}

/* --=[ malloc ]=----------------------------------------------------------- */

#if 1
/* First fit startegy. */
static word_t *find_fit(size_t reqsz)
{
  if (!heap_start)
    return NULL;
  word_t *pointer = heap_start;
  while (1)
  {
    if (bt_free(pointer))
    {
      if (bt_size(pointer) >= reqsz)
        return pointer;
    }
    pointer = bt_next(pointer);
    if (!pointer)
    {
      return NULL;
    }
  }
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
    pointer = mem_sbrk(blocksize);
    if ((long)pointer < 0)
      return NULL;
    if (!heap_start)
      heap_start = pointer;
    last = pointer;
    heap_end = (void *)pointer + blocksize;
    bt_make(pointer, blocksize, USED);
  }
  else // pointer!=NULL
  {
    size_t nonused_size = bt_size(pointer) - blocksize;
    if (nonused_size < ALIGNMENT)
      bt_make(pointer, bt_size(pointer), USED);
    else
    {
      bt_make(pointer, blocksize, USED);
      word_t *nonused_pointer = (void *)pointer + blocksize;
      bt_make(nonused_pointer, nonused_size, FREE);
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
  size_t new_size = bt_size(header);
  word_t *prev_header = bt_prev(header);
  word_t *next_header = bt_next(header);
  int this_last = (last == header);

  //fprintf(stderr, "%ld   %ld   %ld   %ld   %ld   %d\n", (long)heap_start, (long)last, (long)prev_header, (long)header, (long)next_header, (*header));

  if (!this_last && next_header && bt_free(next_header))
  {
    new_size += bt_size(next_header);
    this_last = (last == next_header);
  }

  if (prev_header && bt_free(prev_header))
  {
    new_size += bt_size(prev_header);
    header = prev_header;
  }

  if (this_last)
    last = header;

  bt_make(header, new_size, FREE);
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
  size_t blocksize = blksz(size);
  if (blocksize > bt_size(boundary))
  {
    if (next_boundary && bt_free(next_boundary) && (size_t)bt_size(boundary) + (size_t)bt_size(next_boundary) >= blocksize)
    {
      //fprintf(stderr, "%d %d %ld %ld %d", bt_size(boundary), bt_size(next_boundary), blocksize, bt_size(boundary) + bt_size(next_boundary) - blocksize, bt_size(boundary) + bt_size(next_boundary) - blocksize >= 0);
      size_t nonused_size = bt_size(boundary) + bt_size(next_boundary) - blocksize;
      if (nonused_size < ALIGNMENT)
      {
        if (last == next_boundary)
          last = boundary;
        bt_make(boundary, nonused_size + blocksize, USED);
      }
      else
      {
        bt_make(boundary, blocksize, USED);
        word_t *nonused_pointer = (void *)boundary + blocksize;
        bt_make(nonused_pointer, nonused_size, FREE);
        if (last == next_boundary)
          last = nonused_pointer;
      }
      return old_ptr;
    }
    else //nastepny block za maly lub go nie ma, i musimy przeniesc nasz blok gdzie indziej
    {
      //TODO: MOZNA ZOPTYMALIZOWAC
      void *new_ptr = malloc(size);
      if (!new_ptr)
        return NULL;
      memcpy(new_ptr, old_ptr, bt_size(boundary) - (sizeof(word_t) << 1));
      free(old_ptr);
      return new_ptr;
    }
  }
  else if (blocksize < bt_size(boundary)) // oraz oczywiscie blocksize >= ALIGNMENT
  {
    bt_make(boundary, blocksize, USED);
    if (next_boundary && bt_free(next_boundary))
    {
      if (last == next_boundary)
        last = boundary + blocksize;
      bt_make(boundary + blocksize, bt_size(boundary) + bt_size(next_boundary) - blocksize, FREE);
    }
    else //zauwazmy, ze bt_size(boundary)-blocksize jest wielkosci co najmniej ALIGMENT, bo kazdy z nich jest wielokrotnoscia ALIGMENT
    {
      if (last == boundary)
        last = boundary + blocksize;
      bt_make(boundary + blocksize, bt_size(boundary) - blocksize, FREE);
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

    prev_i = i;
    counter++;
  }

  if (verbose)
  {
    msg("HEAP STRUCTURE\n");
    msg("last:%ld heap_end:%ld\n", (void *)last - (void *)heap_start, (void *)heap_end - (void *)heap_start);
    counter = 0;
    for (void *i = heap_start; i < (void *)heap_end; i += bt_size(i), counter++)
      msg("[%d] header:%d footer:%d size:%d isfree:%d isused:%d islast:%d, Bfirst:%ld,Blast:%ld\n", counter, (*(word_t *)i), (*bt_footer(i)), bt_size(i), bt_free(i), bt_used(i), last == (word_t *)i ? 1 : 0, i - (void *)heap_start, (void *)bt_footer(i) - (void *)heap_start);
    msg("-------------------------------------------\n");
  }
}
