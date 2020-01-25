/*
Tomasz Stachowski, 309675
Jestem jedynym autorem kodu zrodlowego. (zaznaczam, ze korzystam z dolaczonego szkieletu)
*/

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

/* Zostawie DEBUG zdefiniowany, mm_checkheap wypisuje u mnie komunikaty o bledach za pomoca funkcji msg(). */
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
  FREE = 0,               /* Blok jest wolny */
  USED = 1,               /* Blok jest zajety */
  CONTAINER = 2,          /* Blok jest kontenerem */
  FIRST_IN_CONTAINER = 4, /* Blok jest pierwszym blokiem w kontenerze (potrzebne przy podejmowaniu decyzji, czy laczyc wolne bloki) */
} bt_flags;

static word_t *heap_zero;  /* Adres pierwszego slowa zwroconego kiedykolwiek przez mem_sbrk() */
static word_t *heap_start; /* Adres pierwszego bloku */
static word_t *heap_end;   /* Adres pierwszego bajta po ostatnim bloku */
static word_t *last;       /* Wskaznik na ostatni blok */
static word_t *free_lists; /* Wskaznik na tablice list wolnych blokow, jest to tablica offsetow wzgledem heap_zero */

/* Stale */
static const int maxindex = 34;          /* Najwiekszy indeks w tablicy list wolnych blokow, free_lists[maxindex] to lista blokow >= 64MB */
static const int containerexponent = 5;  /* Kontenery zawieraja 2^containerexponent blokow */
static const int maxcontainedsize = 256; /* Maksymalna wielkosc bloku, dla ktorego rozpatrujemy alokacje kontenera */

/* Funkcje pomocnicze do obslugi boundary tagow */

/* Wielkosc bloku */
static inline word_t bt_size(word_t *bt)
{
  return ((*bt) >> 4) << 4;
}

/* Czy blok zajety */
static inline int bt_used(word_t *bt)
{
  return *bt & USED;
}

/* Czy blok wolny */
static inline int bt_free(word_t *bt)
{
  return !(*bt & USED);
}

/* Czy blok jest fragmentem kontenera */
static inline int bt_container(word_t *bt)
{
  return *bt & CONTAINER;
}

/* Czy blok jest wolnym blokiem i fragmentem kontenera */
static inline int bt_freecontainer(word_t *bt)
{
  return bt_container(bt) && bt_free(bt);
}

/* Czy blok jest zajetym blokiem i fragmentem kontenera */
static inline int bt_usedcontainer(word_t *bt)
{
  return bt_container(bt) && bt_used(bt);
}

/* Czy blok jest pierwszym blokiem w kontenerze */
static inline int bt_first_in_container(word_t *bt)
{
  return *bt & FIRST_IN_CONTAINER;
}

/* Adres footera */
static inline word_t *bt_footer(word_t *bt)
{
  return (void *)bt + bt_size(bt) - sizeof(word_t);
}

/* Wskaznik na poczatek bloku wziety ze wskaznika na payload */
static inline word_t *bt_fromptr(void *ptr)
{
  return (word_t *)ptr - 1;
}

/* Tworzy boundary tagi na podstawie wskaznika na blok, wielkosci bloku i flag */
static inline void bt_make(word_t *bt, size_t size, bt_flags flags)
{
  (*bt) = size | flags;
  (*bt_footer(bt)) = size | flags;
}

/* Zwraca adres payloadu */
static inline void *bt_payload(word_t *bt)
{
  return bt + 1;
}

/* Zwraca adres nastepnego bloku lub NULL */
static inline word_t *bt_next(word_t *bt)
{
  if (bt == last)
    return NULL;
  return (void *)bt + bt_size(bt);
}

/* Zwraca adres poprzedniego bloku lub NULL */
static inline word_t *bt_prev(word_t *bt)
{
  if (heap_start == bt)
    return NULL;
  word_t *prevfooter = bt - 1;
  void *prevheader = (void *)prevfooter - bt_size(prevfooter) + sizeof(word_t);
  return prevheader;
}

/* Funkcje pomocnicze do obslugi list wolnych blokow */

/* Zwraca offset na poprzedni blok na liscie */
static inline word_t ls_prev(word_t *ptr)
{
  return *(ptr + 1);
}

/* Zwraca offset na nastepny blok na liscie */
static inline word_t ls_next(word_t *ptr)
{
  return *(ptr + 2);
}

/* Ustawia offset na poprzedni blok na liscie */
static inline void ls_set_prev(word_t *ptr, word_t offset)
{
  *(ptr + 1) = offset;
}

/* Ustawia offset na nastepny blok na liscie */
static inline void ls_set_next(word_t *ptr, word_t offset)
{
  *(ptr + 2) = offset;
}

/* Zwraca adres bloku na podstawie offsetu */
static inline word_t *ls_addrfromoff(word_t offset)
{
  return (word_t *)((void *)heap_zero + (uint64_t)offset);
}

/* Zwraca adres offset na podstawie adresu */
static inline word_t ls_offfromaddr(word_t *pointer)
{
  return (word_t)(uint64_t)((void *)pointer - (uint64_t)heap_zero);
}

/* 
Zwraca indeks w tablicy wolnych blokow na podstawie wielkosci bloku.
Dla blokow o wielkosci mniejszej niz maxcontainedsize indeks rosnie liniowo z wielkoscia tj.
indeks dla wielkosci 16B to 1, indeks dla wielksoci 32B to 2, itd...
Dla blokow o wielkosci wiekszej niz maxcontainedsize indeks rosnie logarytmicznie z wielksocia tj.
indeks dla wielkosci 512B to 17, indeks dla wielkosci 1024B to 18 itd...
*/
static inline int ls_indexfromsize(size_t size)
{
  if (size <= maxcontainedsize)
    return (size + ALIGNMENT - 1) >> 4; //return ceil(size/16);

  size >>= 4;
  long long index;
  asm("bsr %1, %0\n"
      : "=r"(index)
      : "r"(size));
  if (size - ((long long)1 << index) != 0)
    index++;
  return index + 12 < maxindex ? index + 12 : maxindex;
}

/* 
Dodaje blok do odpowiedniej listy wolnych blokow
Bloki w kontenerach maja pierwszenstwo, a wiec sa dodawane na poczatek listy.
Inne wolne bloki sa dodawane na koniec listy.
 */
static inline void ls_add(word_t *block, int index)
{
  if (index == 0)
    index = ls_indexfromsize(bt_size(block));

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

    if (bt_container(block)) //bloki bedace w kontenerach maja pierwszenstwo dlatego wstawiam je na poczatek listy
      free_lists[index] = block_offset;
  }
}

/* Usuwa blok z odpowiedniej listy wolnych blokow */
static inline void ls_remove(word_t *block, int index)
{
  if (index == 0)
    index = ls_indexfromsize(bt_size(block));
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

/* Pozostale procedury pomocnicze */

/* 
Zwraca wielkosc kontenera blokow danego rozmiaru
Kontener ma w sobie 2^containerexponent blokow.
*/
static inline size_t containersize(size_t size)
{
  return size << containerexponent;
}

/* Zwraca wielkosc bloku wraz z miejscem na header, payload/(prev,next), footer oraz padding aby wielkosc bloku byla poddzielna przez 16 */
static inline size_t blksz(size_t size)
{
  size_t payload_and_footer = size + sizeof(word_t);
  if (payload_and_footer % ALIGNMENT == 0)
    return payload_and_footer + ALIGNMENT; //header + payload + footer + padding (wielkosci alignment minus jedno slowo)
  else if (payload_and_footer % ALIGNMENT == ALIGNMENT - sizeof(word_t))
    return sizeof(word_t) + payload_and_footer; //header + payload + footer + padding
  else if (payload_and_footer % ALIGNMENT > ALIGNMENT - sizeof(word_t))
    return payload_and_footer + ALIGNMENT - payload_and_footer % ALIGNMENT + ALIGNMENT;
  else
    return sizeof(word_t) + payload_and_footer + ALIGNMENT - payload_and_footer % ALIGNMENT - sizeof(word_t);
}

/* Prosi o pamiec na stercie do trzymania tablicy offsetow na listy wolnych blokow */
static void *morecore(size_t size)
{
  void *ptr = mem_sbrk(size);
  if (ptr == (void *)-1)
    return NULL;
  return ptr;
}

/* Inicjaliuje sterte, ustawia zmienne globalne i tablice free_lists */

int mm_init(void)
{
  void *ptr = morecore(9 * ALIGNMENT - sizeof(word_t));
  if (!ptr)
    return -1;
  heap_start = NULL;
  heap_zero = memset(ptr, 0, 9 * ALIGNMENT - sizeof(word_t));
  free_lists = heap_zero;
  heap_end = NULL;
  last = NULL;
  return 0;
}

/* Funkcje malloc oraz pomocnicza find_fit znajdujaca wolny blok */

/*
Znajduje adres wolnego bloku na odpowiedniej liscie wolnych blokow.
Na podstawie wielkosci bloku funkcja wyznacza liste wolnych blokow, od ktorych zaczac poszukiwania.
Jezeli blok nie zostanie znaleziony, przeszukujemy listy wiekszych blokow. 
Jezeli nadal nie znajdziemy miejsca na blok, to zwracamy NULL.
Jezeli blok ma wielkosc mniejsza niz maxcontainedsize, to jezeli nie znalezlismy wolnego miejsca o wielkosci dokladnie takiej
samej jak ten blok, to zaczynamy rownolegle szukac miejsca na ten blok, jak i na kontener mieszczacy ten blok na listach wiekszych blokow.
Jezeli znajdziemy miejsce kontener na listach wiekszych blokow, to zwracamy wskaznik na to miejssce.
W przeciwnym wypadku, jezeli znalezlismy miejsce na pojedynczy blok, to zwracamy wskaznik na to miejsce.
W przeciwnym wypadku zwracamy NULL.
*/
static word_t *find_fit(size_t reqsz) // reqsz to szukana wielkosc bloku, a nie payloadu
{
  int index = ls_indexfromsize(reqsz);

  if (reqsz > maxcontainedsize)
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
  else //przypadek dla blokow o malych rozmiarach tj. tych, dla ktorych rozpatrujemy kontenery
  {
    if (free_lists[index] == 0) // nie znalezlismy bloku/kontenera konkretnego rozmiaru, szukamy miejsca na nowy kontener na bloki tego rozmiaru
    {
      size_t old_reqsz = reqsz;
      reqsz = containersize(reqsz);
      index = ls_indexfromsize(reqsz);
      int container_index = index;
      word_t *backup = NULL; // jezeli nie znajdziemy miejsca na kontener, to tu potencjalnie znajduje sie miejsce na pojedynczy blok
      while (index <= maxindex)
      {
        if (free_lists[index] == 0)
        {
          index++;
          continue;
        }
        word_t *first_elem = ls_addrfromoff(free_lists[index]);
        word_t *last_elem = ls_addrfromoff(ls_prev(first_elem));
        word_t *pointer = last_elem;
        do
          if (bt_size(pointer) >= reqsz)
            return pointer;
          else
          {
            pointer = ls_addrfromoff(ls_prev(pointer));
            if (bt_size(pointer) >= old_reqsz && backup == NULL)
              backup = pointer;
          }
        while (pointer != last_elem);
        index++;
      }
      // jezeli nie znajdziemy miejsca na kontener, to probujemy znalezc miejsce na pojedynczy blok
      // taka probe juz podjelismy i wynik jest w zmiennej backup
      // wtedy jednak przeszukiwalismy listy wolnych blokow poczynajac od listy na bardzo duze bloki(mieszczace cale kontenery)
      // teraz przeszukamy mniejsze listy i sprobujemy znalezc blok lepszy od backup(albo jakikolwiek jezeli jeszcze nie mamy zadnego)
      index = ls_indexfromsize(old_reqsz);
      while (index < container_index)
      {
        if (free_lists[index] == 0)
        {
          index++;
          continue;
        }
        word_t *first_elem = ls_addrfromoff(free_lists[index]);
        word_t *last_elem = ls_addrfromoff(ls_prev(first_elem));
        word_t *pointer = last_elem;
        do
          if (bt_size(pointer) >= old_reqsz && !bt_container(pointer))
            return pointer;
          else
            pointer = ls_addrfromoff(ls_prev(pointer));
        while (pointer != last_elem);
        index++;
      }
      if (backup)
        return backup; //zwrocimy backup kiedy znajdziemy odpowiednio duzy blok na listach na bloki mieszczace cale kontenery, ale nie na mniejszych
    }
    else
      return ls_addrfromoff(free_lists[index]);
  }
  return NULL;
}

/*
Funkcja malloc najpierw wywoluje find_fit.
Jezeli find_fit zwrocil NULL, to malloc patrzy czy sterta jest pusta oraz czy ostatni blok jest wolny (i nie jest w kontenerze).
Jezeli sterta jest pusta lub ostatni blok nie jest wolny (lub jest w kontenerze), to 
malloc powieksza sterte o wielkosc bloku (w przypadku blokow wiekszych niz maxcontainedsize) 
lub powieksza sterte o wielkosc kontenera na blok (w przypadku blokow mniejszych/rownych maxcontainedsize).
Nastepnie nowe miejsce oznacza jako zajety blok, tudziez jako dwa bloki w nowym kontenerze, pierwszy zajety, a drugi wolny.
Jezeli find_fit zwrocil adres jakiegos bloku, to malloc w zaleznosci od wielkosci bloku, na ktory dostal adres
albo oznacza go calego jako zajety, albo dzieli go na czesci i oznacza je jako zajeta i wolna.
W przypadku malych blokow malloc na podstawie wielkosci wolnego miejsca rozpatruje czy oznaczyc je jako kontener.
Tak wiec np. w przypadku odpowiednio duzego wolnego miejsca, malloc stworzy trzy bloki:
zajety blok wielkosci x, pozostale miejsce w kontenerze na bloki rozmiaru x, wolny blok.
*/
void *malloc(size_t size)
{
  size_t blocksize = blksz(size);
  word_t *pointer = find_fit(blocksize);
  if (pointer == NULL)
  {
    if (heap_start && bt_free(last) && !bt_container(last))
    {
      ls_remove(last, 0);
      if (blocksize > maxcontainedsize)
      {
        mem_sbrk(blocksize - bt_size(last));
        heap_end = (void *)heap_end + blocksize - bt_size(last);
        bt_make(last, blocksize, USED);
        return bt_payload(last);
      }
      else //male bloki, przypadek z kontenerami
      {
        mem_sbrk(containersize(blocksize) - bt_size(last));
        heap_end = (void *)heap_end + containersize(blocksize) - bt_size(last);
        bt_make(last, blocksize, USED | CONTAINER | FIRST_IN_CONTAINER);
        bt_make((void *)last + blocksize, containersize(blocksize) - blocksize, FREE | CONTAINER);
        ls_add((void *)last + blocksize, ls_indexfromsize(blocksize));
        word_t *old_last = last;
        last = (void *)last + blocksize;
        return bt_payload(old_last);
      }
    }
    else // pusta sterta lub na koncu sterty nie ma wolnego bloku
    {
      if (blocksize > maxcontainedsize)
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
      else //male bloki, przypadek z kontenerami
      {
        pointer = mem_sbrk(containersize(blocksize));
        if ((long)pointer < 0)
          return NULL;
        if (!heap_start)
          heap_start = pointer;
        heap_end = (void *)pointer + containersize(blocksize);
        bt_make(pointer, blocksize, USED | CONTAINER | FIRST_IN_CONTAINER);
        bt_make((void *)pointer + blocksize, containersize(blocksize) - blocksize, FREE | CONTAINER);
        ls_add((void *)pointer + blocksize, ls_indexfromsize(blocksize));
        last = (void *)pointer + blocksize;
      }
    }
  }
  else // pointer!=NULL
  {
    size_t nonused_size = bt_size(pointer) - blocksize;
    word_t *nonused_pointer = (void *)pointer + blocksize;
    if (nonused_size < ALIGNMENT) //bedzie tak samo dla malych jak i duzych blokow
    {
      ls_remove(pointer, 0);
      bt_make(pointer, bt_size(pointer), USED | bt_container(pointer) | bt_first_in_container(pointer));
    }
    else
    {
      if (blocksize > maxcontainedsize)
      {
        ls_remove(pointer, 0);
        bt_make(pointer, blocksize, USED);
        bt_make(nonused_pointer, nonused_size, FREE);
        ls_add(nonused_pointer, 0);
        if (last == pointer)
          last = nonused_pointer;
      }
      else //male bloki, przypadek z kontenerami
      {
        if (bt_container(pointer)) //znalezlismy wolne miejsce w kontenerze na blok rozmiaru blocksize
        {
          ls_remove(pointer, ls_indexfromsize(blocksize));
          bt_make(pointer, blocksize, USED | CONTAINER | bt_first_in_container(pointer));
          bt_make(nonused_pointer, nonused_size, FREE | CONTAINER);
          ls_add(nonused_pointer, ls_indexfromsize(blocksize));
          if (last == pointer)
            last = nonused_pointer;
        }
        else if (bt_size(pointer) >= containersize(blocksize)) //nie znalezlismy pasujacego kontenera, ale na jednej z list znalezlismy wystarczajace miejsce na nowy kontener
        {
          // ten przypadek jest najbardziej trikowy, powstaja tu trzy rozne bloki
          ls_remove(pointer, 0);
          size_t noncontained_size = bt_size(pointer) - containersize(blocksize);
          word_t *noncontained_pointer = (void *)pointer + containersize(blocksize);
          bt_make(pointer, blocksize, USED | CONTAINER | FIRST_IN_CONTAINER);
          bt_make(nonused_pointer, containersize(blocksize) - blocksize, FREE | CONTAINER);
          bt_make(noncontained_pointer, noncontained_size, FREE);
          ls_add(nonused_pointer, ls_indexfromsize(blocksize));
          ls_add(noncontained_pointer, 0);
          if (last == pointer)
            last = noncontained_pointer;
        }
        else //znalezlismy odpowiednio duzy wolny blok na przechowanie pojedynczego bloku wielkosci blocksize
        {
          ls_remove(pointer, 0);
          bt_make(pointer, blocksize, USED);
          bt_make(nonused_pointer, nonused_size, FREE);
          ls_add(nonused_pointer, 0);
          if (last == pointer)
            last = nonused_pointer;
        }
      }
    }
  }
  return bt_payload(pointer);
}

/*
Funkcja free zwalnia blok, na ktorego payload wskazuje ptr.
Funkcja sprawdza tez, czy na lewo i na prawo w pamieci od zwalnianego bloku znajduja sie wolne bloki.
W przypadku, gdy zwalniany blok jest w kontenerze, to funkcja sprawdza, 
czy ewentualne wolne bloki na lewo i na prawo sa fragmentem tego samego kontenera.
Jezeli na lewo lub na prawo w pamieci od zwalnianeo bloku mamy wolne bloki(ew. nalezace takze do tego samego kontenera),
to funkcja laczy te bloki w jeden nowy wiekszy wolny blok.
Jezeli zwalniany blok jest w kontenerze i okaze sie, ze po zwolnieniu caly kontener jest pusty,
to kontener jest "usuwany" tj. nowy wolny blok nie jest juz oznaczony flaga CONTAINER. 
*/

void free(void *ptr)
{
  if (ptr == NULL)
    return;
  word_t *header = bt_fromptr(ptr);
  if (bt_free(header))
    return;
  size_t old_size = bt_size(header);
  size_t new_size = old_size;
  int index = 0;
  int delete_container = 0;
  word_t *container_to_delete = NULL;
  word_t *prev_header = bt_prev(header);
  word_t *next_header = bt_next(header);
  int next_is_free = next_header && bt_free(next_header);
  next_is_free = next_is_free && ((bt_container(header) && bt_container(next_header)) || (!bt_container(header) && !bt_container(next_header)));

  int prev_is_free = prev_header && bt_free(prev_header);
  prev_is_free = prev_is_free && ((bt_container(header) && bt_container(prev_header)) || (!bt_container(header) && !bt_container(prev_header)));

  if (bt_container(header))
  {
    prev_is_free = prev_is_free && !bt_first_in_container(header);
    next_is_free = next_is_free && !bt_first_in_container(next_header);
    index = ls_indexfromsize(new_size);
  }

  if (next_is_free && prev_is_free)
  {
    if (next_header == last)
      last = prev_header;
    ls_remove(prev_header, index);
    ls_remove(next_header, index);
    new_size += bt_size(prev_header) + bt_size(next_header);
    bt_make(prev_header, new_size, FREE | bt_container(header) | bt_first_in_container(prev_header));
    if (bt_container(prev_header) && (new_size == containersize(old_size)))
    {
      bt_make(prev_header, new_size, USED);
      delete_container = 1;
      container_to_delete = prev_header;
    }
    else
      ls_add(prev_header, index);
  }
  else if (next_is_free)
  {
    if (next_header == last)
      last = header;
    ls_remove(next_header, index);
    new_size += bt_size(next_header);
    bt_make(header, new_size, FREE | bt_container(header) | bt_first_in_container(header));
    if (bt_container(header) && (new_size == containersize(old_size)))
    {
      bt_make(header, new_size, USED);
      delete_container = 1;
      container_to_delete = header;
    }
    else
      ls_add(header, index);
  }
  else if (prev_is_free)
  {
    if (header == last)
      last = prev_header;
    ls_remove(prev_header, index);
    new_size += bt_size(prev_header);
    bt_make(prev_header, new_size, FREE | bt_container(header) | bt_first_in_container(prev_header));
    if (bt_container(prev_header) && (new_size == containersize(old_size)))
    {
      bt_make(prev_header, new_size, USED);
      delete_container = 1;
      container_to_delete = prev_header;
    }
    else
      ls_add(prev_header, index);
  }
  else //no adjacent free blocks
  {
    bt_make(header, new_size, FREE | bt_container(header) | bt_first_in_container(header)); // new_size to stara dlugosc w tym przypadku
    if (bt_container(header) && (new_size == containersize(old_size)))
    {
      bt_make(header, new_size, USED);
      delete_container = 1;
      container_to_delete = header;
    }
    else
      ls_add(header, index);
  }

  if (delete_container)
    free(bt_payload(container_to_delete));
}

/* 
Funkcja realloc powieksza/zmniejsza blok.

Jezeli blok jest w kontenerze, to jezeli blok ma byc zmniejszony, to funkcja nie robi nic,
a jezeli blok ma byc zwiekszony to funkcja mallocuje go na nowo.

Jezeli blok nie jest w kontenerze, to jezeli blok ma byc zwiekszony, to funkcja patrzy
na bloki na lewo i na prawo od niego i sprawdza, 
czy sa wolne oraz czy sumarycznie starcza na przechowanie nowego powiekszonego bloku.
Jezeli sumaryczne miejsce blokow (danego, na lewo od niego i na prawo od niego) starcza na przechowanie powiekszonego bloku,
to jest on odpowiednio kopiowany,przesuwany i funkcja zwraca na niego wskaznik.
Niektore operacje maja wyzszy priorytet niz inne, tak aby kopiowanie pamieci odbylo sie tylko, jezeli jest niezbedne.
Przykladowo, jezeli powiekszony blok miesci sie w starym bloku + bloku na prawo od niego,
to algorytm nawet nie sprawdzi, czy blok na lewo jest wolny.
Jezeli okaze sie, ze powiekszony blok nie miesci sie w sumie wolnych blokow naokolo danego bloku,
to funkcja mallocuje go na nowo.
Duza optymalizacja jest to, ze gdy funkcja realloc mallocuje blok na nowo, to najpierw wykonywany jest free, a dopiero potem malloc.
Funkcja free nadpisuje payload starego bloku dwoma offsetami na adresy blokow na liscie wolnych blokow,
tak wiec trzeba przechowac dwa slowa z bloku w zmiennych pomocniczych, a dopiero potem wywolac free.

W przypadku gdy blok jest zmniejszany i nie jest kontenerem, to zmniejszany jest w miejscu.
*/

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

  if (bt_container(boundary))
  {
    if (blocksize <= bt_size(boundary))
      return old_ptr;
    else
    {
      size_t newsize = (size > 2 * bt_size(boundary) - 4 * sizeof(word_t)) ? size : 2 * bt_size(boundary) - 4 * sizeof(word_t);
      newsize = size;
      word_t word1 = (*(word_t *)old_ptr);
      word_t word2 = (*((word_t *)old_ptr + 1));
      free(old_ptr);
      void *new_ptr = malloc(newsize);
      if (!new_ptr)
        return NULL;
      (*(word_t *)new_ptr) = word1;
      (*((word_t *)new_ptr + 1)) = word2;
      memcpy((word_t *)new_ptr + 2, (word_t *)old_ptr + 2, bt_size(boundary) - (sizeof(word_t) << 2));
      return new_ptr;
    }
  }

  int next_is_free = next_boundary && bt_free(next_boundary) && !bt_container(next_boundary);
  int prev_is_free = prev_boundary && bt_free(prev_boundary) && !bt_container(prev_boundary);

  if (blocksize > bt_size(boundary))
  {
    if (next_is_free && next_boundary == last && (size_t)bt_size(boundary) + (size_t)bt_size(next_boundary) < blocksize)
    {
      ls_remove(next_boundary, 0);
      mem_sbrk(blocksize - (size_t)bt_size(boundary) - (size_t)bt_size(next_boundary));
      heap_end = (void *)heap_end + blocksize - (size_t)bt_size(boundary) - (size_t)bt_size(next_boundary);
      last = boundary;
      bt_make(boundary, blocksize, USED);
      return old_ptr;
    }
    else if (next_is_free && (size_t)bt_size(boundary) + (size_t)bt_size(next_boundary) >= blocksize)
    {
      size_t nonused_size = bt_size(boundary) + bt_size(next_boundary) - blocksize;
      if (nonused_size < ALIGNMENT)
      {
        if (last == next_boundary)
          last = boundary;
        ls_remove(next_boundary, 0);
        bt_make(boundary, nonused_size + blocksize, USED);
      }
      else
      {
        ls_remove(next_boundary, 0);
        bt_make(boundary, blocksize, USED);
        word_t *nonused_pointer = (void *)boundary + blocksize;
        bt_make(nonused_pointer, nonused_size, FREE);
        ls_add(nonused_pointer, 0);
        if (last == next_boundary)
          last = nonused_pointer;
      }
      return old_ptr;
    }
    else if (next_is_free && prev_is_free && (size_t)bt_size(boundary) + (size_t)bt_size(boundary) + (size_t)bt_size(next_boundary) >= blocksize)
    {
      size_t nonused_size = bt_size(prev_boundary) + bt_size(boundary) + bt_size(next_boundary) - blocksize;
      if (nonused_size < ALIGNMENT)
      {
        if (last == next_boundary)
          last = prev_boundary;
        ls_remove(prev_boundary, 0);
        ls_remove(next_boundary, 0);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize + nonused_size, USED);
      }
      else
      {
        word_t *nonused_pointer = (void *)prev_boundary + blocksize;
        ls_remove(prev_boundary, 0);
        ls_remove(next_boundary, 0);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize, USED);
        bt_make(nonused_pointer, nonused_size, FREE);
        ls_add(nonused_pointer, 0);
        if (last == next_boundary)
          last = nonused_pointer;
      }
      return bt_payload(prev_boundary);
    }
    else if (prev_is_free && (size_t)bt_size(prev_boundary) + (size_t)bt_size(boundary) >= blocksize)
    {
      size_t nonused_size = bt_size(prev_boundary) + bt_size(boundary) - blocksize;
      if (nonused_size < ALIGNMENT)
      {
        if (last == boundary)
          last = prev_boundary;
        ls_remove(prev_boundary, 0);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize + nonused_size, USED);
      }
      else
      {
        word_t *nonused_pointer = (void *)prev_boundary + blocksize;
        ls_remove(prev_boundary, 0);
        memcpy(bt_payload(prev_boundary), bt_payload(boundary), bt_size(boundary) - 2 * sizeof(word_t));
        bt_make(prev_boundary, blocksize, USED);
        bt_make(nonused_pointer, nonused_size, FREE);
        ls_add(nonused_pointer, 0);
        if (last == boundary)
          last = nonused_pointer;
      }
      return bt_payload(prev_boundary);
    }
    else
    {
      size_t newsize = (size > 2 * bt_size(boundary) - 4 * sizeof(word_t)) ? size : 2 * bt_size(boundary) - 4 * sizeof(word_t);
      newsize = size;
      word_t word1 = (*(word_t *)old_ptr);
      word_t word2 = (*((word_t *)old_ptr + 1));
      free(old_ptr);
      void *new_ptr = malloc(newsize);
      if (!new_ptr)
        return NULL;
      (*(word_t *)new_ptr) = word1;
      (*((word_t *)new_ptr + 1)) = word2;
      memcpy((word_t *)new_ptr + 2, (word_t *)old_ptr + 2, bt_size(boundary) - (sizeof(word_t) << 2));
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
      word_t *nonused_pointer = (void *)boundary + blocksize;
      bt_make(nonused_pointer, bt_size(boundary) + bt_size(next_boundary) - blocksize, FREE);
      ls_add(nonused_pointer, 0);
    }
    else //zauwazmy, ze bt_size(boundary)-blocksize jest wielkosci co najmniej ALIGMENT, bo kazdy z nich jest wielokrotnoscia ALIGMENT
    {
      word_t *new_block = (void *)boundary + blocksize;
      if (last == boundary)
        last = new_block;
      bt_make(new_block, bt_size(boundary) - blocksize, FREE);
      ls_add(new_block, 0);
    }
    return old_ptr;
  }
  else
    return old_ptr;
}

/* Funkcja alokuje pamiec za pomoca malloc i zeruje ja */

void *calloc(size_t nmemb, size_t size)
{
  size_t bytes = nmemb * size;
  void *new_ptr = malloc(bytes);
  if (new_ptr)
    memset(new_ptr, 0, bytes);
  return new_ptr;
}

/* Funkcja sprawdzajaca poprawnosc danych algorytmu zarzadzania pamiecia. */
void mm_checkheap(int verbose)
{
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

    if (!bt_container(i) && bt_first_in_container(i))
      msg("[%d] CHECKHEAP ERROR: BLOCK NOT IN A CONTAINER BUT MARKED AS FIRST IN CONTAINER\n", counter);

    if (bt_free(i) && bt_used(i))
      msg("[%d] CHECKHEAP ERROR: BLOCK BOTH FREE AND USED\n", counter);

    if (bt_size(i) % 16)
      msg("[%d] CHECKHEAP ERROR: SIZE NOT DIVISIBLE BY 16\n", counter);

    if (bt_container(i) && bt_size(i) > containersize(maxcontainedsize))
      msg("[%d] CHECKHEAP ERROR: SIZE NOT DIVISIBLE BY 16\n", counter);

    if ((long)bt_payload(i) % 16)
      msg("[%d] CHECKHEAP ERROR: PAYLOAD ADDRESS NOT DIVISIBLE BY 16\n", counter);

    if (prev_i && bt_free(prev_i) && bt_free(i) && !bt_container(i) && !bt_container(prev_i))
      msg("[%d] [%d] CHECKHEAP ERROR: TWO FREE NONCONTAINER BLOCKS ADJACENT\n", counter - 1, counter);
    prev_i = i;
    counter++;
  }

  for (int index = 1; index <= maxindex; index++)
  {
    if (free_lists[index] == 0)
    {
      index++;
      continue;
    }
    word_t *first_elem = ls_addrfromoff(free_lists[index]);
    word_t *pointer = first_elem;
    do
    {
      if (!bt_free(pointer))
        msg("[Free Lists,index=%d] CHECKHEAP ERROR: Block on a free list is not free\n", index);
      pointer = ls_addrfromoff(ls_next(pointer));
    } while (pointer != first_elem);
    index++;
  }
}