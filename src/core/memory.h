/* Use of this source code is governed by the Apache 2.0 license; see COPYING. */

int      lock_memory();
void    *allocate_huge_page(int size);
uint64_t phys_page(uint64_t virt_page);

