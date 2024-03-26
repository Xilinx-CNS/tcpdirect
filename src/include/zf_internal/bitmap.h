/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: (c) Advanced Micro Devices, Inc. */
/** bitmap - basic implementation of fixed size bitmap */


#ifndef __BITMAP_H__
#define __BITMAP_H__

template <int _BIT_COUNT>
struct zf_bitmap {
  typedef uint64_t word;
  static const unsigned BIT_COUNT = _BIT_COUNT;
  static const unsigned WORD_BIT_COUNT = sizeof(word) * 8;
  static const unsigned WORD_COUNT = BIT_COUNT / WORD_BIT_COUNT;

  word b[WORD_COUNT];
};

template <typename WORD> static inline void
zf_bitmap_word_clear_bit(WORD* w, unsigned b)
{
  zf_assert_le(b, sizeof(WORD) * 8);
  *w &= ~(((WORD)1) << b);
}

template <int BC> static inline void
zf_bitmap_clear_bit(zf_bitmap<BC>* bm, unsigned b)
{
  zf_assert_le(b, zf_bitmap<BC>::BIT_COUNT);
  zf_bitmap_word_clear_bit(bm->b + b / zf_bitmap<BC>::WORD_BIT_COUNT,
                           b & (zf_bitmap<BC>::WORD_BIT_COUNT-1));
}

template <typename WORD> static inline void
zf_bitmap_word_set_bit(WORD* w, unsigned b)
{
  zf_assert_le(b, sizeof(WORD) * 8);
  *w |= (((WORD)1) << b);
}

template <int BC> static inline void
zf_bitmap_set_bit(zf_bitmap<BC>* bm, unsigned b)
{
  zf_assert_le(b, zf_bitmap<BC>::BIT_COUNT);
  zf_bitmap_word_set_bit(bm->b + b / zf_bitmap<BC>::WORD_BIT_COUNT,
                         b & (zf_bitmap<BC>::WORD_BIT_COUNT-1));
}

template <typename WORD> static inline int
zf_bitmap_word_test_bit(WORD* w, unsigned b)
{
  zf_assert_le(b, sizeof(WORD) * 8);
  return (*w & (((WORD)1) << b)) != 0;
}


template <int BC> static inline int
zf_bitmap_test_bit(zf_bitmap<BC>* bm, unsigned b)
{
  zf_assert_le(b, zf_bitmap<BC>::BIT_COUNT);
  return zf_bitmap_word_test_bit(bm->b + b / zf_bitmap<BC>::WORD_BIT_COUNT,
                                 b & (zf_bitmap<BC>::WORD_BIT_COUNT-1));
}

template <typename WORD> static inline int
zf_bitmap_word_pop_bit(WORD* w)
{
  zf_assert_nequal(*w, 0);
  int b = __builtin_ffsll(*w);
  zf_bitmap_word_clear_bit(w, b - 1);
  return b - 1;
}


template <int BC> static inline void
zf_bitmap_join_and_reset(zf_bitmap<BC>* bucket1, zf_bitmap<BC>* bucket2)
{
  typename zf_bitmap<BC>::word *b1 = bucket1->b;
  typename zf_bitmap<BC>::word *b2 = bucket2->b;
  for( ; b1 < bucket1->b + zf_bitmap<BC>::WORD_COUNT; ++b1, ++b2) {
    *b1 |= *b2;
    *b2 = 0;
  }
}

#endif /* __BITMAP_H__ */
