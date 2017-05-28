/* -*- linux-c -*- 
 * map API generator
 * Copyright (C) 2005-2016 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

/** @file map-gen.c
 * @brief Map function generator
 * This file is a template designed to be included as many times as
 * needed to generate the necessary map functions.
 */

#define JOIN(x,y) JOINx(x,y)
#define JOINx(x,y) x##_##y
#define JOIN2(x,y,z) JOIN2x(x,y,z)
#define JOIN2x(x,y,z) x##_##y##z
#define JOIN3(a,b,c,d) JOIN3x(a,b,c,d)
#define JOIN3x(a,b,c,d) a##_##b##c##d
#define JOIN4(a,b,c,d,e) JOIN4x(a,b,c,d,e)
#define JOIN4x(a,b,c,d,e) a##_##b##c##d##e
#define JOIN5(a,b,c,d,e,f) JOIN5x(a,b,c,d,e,f)
#define JOIN5x(a,b,c,d,e,f) a##_##b##c##d##e##f
#define JOIN6(a,b,c,d,e,f,g) JOIN6x(a,b,c,d,e,f,g)
#define JOIN6x(a,b,c,d,e,f,g) a##_##b##c##d##e##f##g
#define JOIN7(a,b,c,d,e,f,g,h) JOIN7x(a,b,c,d,e,f,g,h)
#define JOIN7x(a,b,c,d,e,f,g,h) a##_##b##c##d##e##f##g##h
#define JOIN8(a,b,c,d,e,f,g,h,i) JOIN8x(a,b,c,d,e,f,g,h,i)
#define JOIN8x(a,b,c,d,e,f,g,h,i) a##_##b##c##d##e##f##g##h##i
#define JOIN9(a,b,c,d,e,f,g,h,i,j) JOIN9x(a,b,c,d,e,f,g,h,i,j)
#define JOIN9x(a,b,c,d,e,f,g,h,i,j) a##_##b##c##d##e##f##g##h##i##j
#define JOIN10(a,b,c,d,e,f,g,h,i,j,k) JOIN10x(a,b,c,d,e,f,g,h,i,j,k)
#define JOIN10x(a,b,c,d,e,f,g,h,i,j,k) a##_##b##c##d##e##f##g##h##i##j##k

#include "map.h"

#if !defined(VALUE_TYPE)
#error Need to define VALUE_TYPE as STRING, STAT, or INT64
#endif

#if VALUE_TYPE == STRING
#define VALTYPE char*
#define VSTYPE char*
#define VALNAME str
#define VALN s
#define VALSTOR char value[MAP_STRING_LENGTH]
#define MAP_GET_VAL(node) ((node)->value)
#define MAP_SET_VAL(map,node,val,add) _new_map_set_str(map,MAP_GET_VAL(node),val,add)
#define MAP_COPY_VAL(map,node,val,add) MAP_SET_VAL(map,node,val,add)
#define NULLRET ""
#elif VALUE_TYPE == INT64
#define VALTYPE int64_t
#define VSTYPE int64_t
#define VALNAME int64
#define VALN i
#define VALSTOR int64_t value
#define MAP_GET_VAL(node) ((node)->value)
#define MAP_SET_VAL(map,node,val,add) _new_map_set_int64(map,&MAP_GET_VAL(node),val,add)
#define MAP_COPY_VAL(map,node,val,add) MAP_SET_VAL(map,node,val,add)
#define NULLRET (int64_t)0
#elif VALUE_TYPE == STAT
#define VALTYPE stat_data*
#define VSTYPE int64_t
#define VALNAME stat_data
#define VALN x
#define VALSTOR stat_data value
#define MAP_GET_VAL(node) (&(node)->value)
#define MAP_SET_VAL(map,node,val,add) _new_map_set_stat(map,MAP_GET_VAL(node),val,add)
#define MAP_COPY_VAL(map,node,val,add) _new_map_copy_stat(map,MAP_GET_VAL(node),val,add)
#define NULLRET (stat_data*)0
#else
#error Need to define VALUE_TYPE as STRING, STAT, or INT64
#endif /* VALUE_TYPE */


/* murmurhash3 body, for use in KEYSYM(hash)
   Extracted from
   https://github.com/aappleby/smhasher/tree/master/src
   -----------------------------------------------------------------------------
   MurmurHash3 was written by Austin Appleby, and is placed in the public
   domain. The author hereby disclaims copyright to this source code.
   -----------------------------------------------------------------------------
*/
#define ROTL32(x,r) (((uint32_t)x << r) | ((uint32_t)x >> (32 - r)))

#define MURMUR_INT64(v) do {                   \
                uint32_t k1;                    \
                k1 = (v & 0xFFFFFFFF);                  \
                k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2;             \
                h1 ^= k1; h1 = ROTL32(h1,13); h1 = h1*5+0xe6546b64; \
                k1 = ((v >> 32) & 0xFFFFFFFF);                      \
                k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2;                 \
                h1 ^= k1; h1 = ROTL32(h1,13); h1 = h1*5+0xe6546b64;     \
                len += 8;                                               \
        } while(0)
#define MURMUR_STRING(v) do { \
                uint32_t mylen = strlen(v); \
                int nblocks = mylen / 4; \
                const uint32_t * blocks = (const uint32_t *)(v + nblocks*4); \
                const uint8_t * tail; \
                uint32_t k1; \
                int i; \
                for(i = -nblocks; i; i++)  { \
                        uint32_t k1 = blocks[i]; \
                        k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; \
                        h1 ^= k1; h1 = ROTL32(h1,13); h1 = h1*5+0xe6546b64; \
                } \
                tail = (const uint8_t*)(v + nblocks*4); \
                k1 = 0; \
                switch(mylen & 3) {                \
                case 3: k1 ^= tail[2] << 16; \
                case 2: k1 ^= tail[1] << 8; \
                case 1: k1 ^= tail[0]; \
                        k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1; \
                } \
                len += mylen; \
        } while (0)

        
#if defined (KEY1_TYPE)
#define KEY_ARITY 1
#if KEY1_TYPE == STRING
#define KEY1TYPE char*
#define KEY1NAME str
#define KEY1N s
#define KEY1STOR char key1[MAP_STRING_LENGTH]
#define KEY1CPY(m) str_copy(m->key1, key1)
#define KEY1_HASH MURMUR_STRING(key1)
#else
#define KEY1TYPE int64_t
#define KEY1NAME int64
#define KEY1N i
#define KEY1STOR int64_t key1
#define KEY1CPY(m) m->key1=key1

/* Instead of ...
   #define KEY1_HASH MURMUR_INT64(key1)

   We could do the quick & dirty kernel hash_64 for the first integer index.
   This would be faster, and may give reasonable dispersion with the
   retained final 32-bit mix.
   #define KEY1_HASH h1 ^= hash_64(key1,32)

   ... but hashing throughput is only slightly faster
*/
#define KEY1_HASH MURMUR_INT64(key1)
#endif
#define KEY1_EQ_P JOIN(KEY1NAME,eq_p)
#endif /* defined(KEY1_TYPE) */

#if defined (KEY2_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 2
#if KEY2_TYPE == STRING
#define KEY2TYPE char*
#define KEY2NAME str
#define KEY2N s
#define KEY2STOR char key2[MAP_STRING_LENGTH]
#define KEY2CPY(m) str_copy(m->key2, key2)
#define KEY2_HASH MURMUR_STRING(key2)
#else
#define KEY2TYPE int64_t
#define KEY2NAME int64
#define KEY2N i
#define KEY2STOR int64_t key2
#define KEY2CPY(m) m->key2=key2
#define KEY2_HASH MURMUR_INT64(key2)
#endif
#define KEY2_EQ_P JOIN(KEY2NAME,eq_p)
#endif /* defined(KEY2_TYPE) */

#if defined (KEY3_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 3
#if KEY3_TYPE == STRING
#define KEY3TYPE char*
#define KEY3NAME str
#define KEY3N s
#define KEY3STOR char key3[MAP_STRING_LENGTH]
#define KEY3CPY(m) str_copy(m->key3, key3)
#define KEY3_HASH MURMUR_STRING(key3)
#else
#define KEY3TYPE int64_t
#define KEY3NAME int64
#define KEY3N i
#define KEY3STOR int64_t key3
#define KEY3CPY(m) m->key3=key3
#define KEY3_HASH MURMUR_INT64(key3)
#endif
#define KEY3_EQ_P JOIN(KEY3NAME,eq_p)
#endif /* defined(KEY3_TYPE) */

#if defined (KEY4_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 4
#if KEY4_TYPE == STRING
#define KEY4TYPE char*
#define KEY4NAME str
#define KEY4N s
#define KEY4STOR char key4[MAP_STRING_LENGTH]
#define KEY4CPY(m) str_copy(m->key4, key4)
#define KEY4_HASH MURMUR_STRING(key4)
#else
#define KEY4TYPE int64_t
#define KEY4NAME int64
#define KEY4N i
#define KEY4STOR int64_t key4
#define KEY4CPY(m) m->key4=key4
#define KEY4_HASH MURMUR_INT64(key4)
#endif
#define KEY4_EQ_P JOIN(KEY4NAME,eq_p)
#endif /* defined(KEY4_TYPE) */

#if defined (KEY5_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 5
#if KEY5_TYPE == STRING
#define KEY5TYPE char*
#define KEY5NAME str
#define KEY5N s
#define KEY5STOR char key5[MAP_STRING_LENGTH]
#define KEY5CPY(m) str_copy(m->key5, key5)
#define KEY5_HASH MURMUR_STRING(key5)
#else
#define KEY5TYPE int64_t
#define KEY5NAME int64
#define KEY5N i
#define KEY5STOR int64_t key5
#define KEY5CPY(m) m->key5=key5
#define KEY5_HASH MURMUR_INT64(key5)
#endif
#define KEY5_EQ_P JOIN(KEY5NAME,eq_p)
#endif /* defined(KEY5_TYPE) */

#if defined (KEY6_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 6
#if KEY6_TYPE == STRING
#define KEY6TYPE char*
#define KEY6NAME str
#define KEY6N s
#define KEY6STOR char key6[MAP_STRING_LENGTH]
#define KEY6CPY(m) str_copy(m->key6, key6)
#define KEY6_HASH MURMUR_STRING(key6)
#else
#define KEY6TYPE int64_t
#define KEY6NAME int64
#define KEY6N i
#define KEY6STOR int64_t key6
#define KEY6CPY(m) m->key6=key6
#define KEY6_HASH MURMUR_INT64(key6)
#endif
#define KEY6_EQ_P JOIN(KEY6NAME,eq_p)
#endif /* defined(KEY6_TYPE) */

#if defined (KEY7_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 7
#if KEY7_TYPE == STRING
#define KEY7TYPE char*
#define KEY7NAME str
#define KEY7N s
#define KEY7STOR char key7[MAP_STRING_LENGTH]
#define KEY7CPY(m) str_copy(m->key7, key7)
#define KEY7_HASH MURMUR_STRING(key7)
#else
#define KEY7TYPE int64_t
#define KEY7NAME int64
#define KEY7N i
#define KEY7STOR int64_t key7
#define KEY7CPY(m) m->key7=key7
#define KEY7_HASH MURMUR_INT64(key7)
#endif
#define KEY7_EQ_P JOIN(KEY7NAME,eq_p)
#endif /* defined(KEY7_TYPE) */

#if defined (KEY8_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 8
#if KEY8_TYPE == STRING
#define KEY8TYPE char*
#define KEY8NAME str
#define KEY8N s
#define KEY8STOR char key8[MAP_STRING_LENGTH]
#define KEY8CPY(m) str_copy(m->key8, key8)
#define KEY8_HASH MURMUR_STRING(key8)
#else
#define KEY8TYPE int64_t
#define KEY8NAME int64
#define KEY8N i
#define KEY8STOR int64_t key8
#define KEY8CPY(m) m->key8=key8
#define KEY8_HASH MURMUR_INT64(key8)
#endif
#define KEY8_EQ_P JOIN(KEY8NAME,eq_p)
#endif /* defined(KEY8_TYPE) */

#if defined (KEY9_TYPE)
#undef KEY_ARITY
#define KEY_ARITY 9
#if KEY9_TYPE == STRING
#define KEY9TYPE char*
#define KEY9NAME str
#define KEY9N s
#define KEY9STOR char key9[MAP_STRING_LENGTH]
#define KEY9CPY(m) str_copy(m->key9, key9)
#define KEY9_HASH MURMUR_STRING(key9)
#else
#define KEY9TYPE int64_t
#define KEY9NAME int64
#define KEY9N i
#define KEY9STOR int64_t key9
#define KEY9CPY(m) m->key9=key9
#define KEY9_HASH MURMUR_INT64(key9)
#endif
#define KEY9_EQ_P JOIN(KEY9NAME,eq_p)
#endif /* defined(KEY9_TYPE) */

/* Not so many, cowboy! */
#if defined (KEY10_TYPE)
#error "excessive key arity == too many array indexes"
#endif



#if KEY_ARITY == 1
#define KEYSYM(x) JOIN2(x,KEY1N,VALN)
#define ALLKEYS(x) x##1
#define ALLKEYSD(x) KEY1TYPE x##1
#define KEYCPY(m) {KEY1CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1))
#elif KEY_ARITY == 2
#define KEYSYM(x) JOIN3(x,KEY1N,KEY2N,VALN)
#define ALLKEYS(x) x##1, x##2
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2))
#elif KEY_ARITY == 3
#define KEYSYM(x) JOIN4(x,KEY1N,KEY2N,KEY3N,VALN)
#define ALLKEYS(x) x##1, x##2, x##3
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2, KEY3TYPE x##3
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);KEY3CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2) && KEY3_EQ_P(m->key3,key3))
#elif KEY_ARITY == 4
#define KEYSYM(x) JOIN5(x,KEY1N,KEY2N,KEY3N,KEY4N,VALN)
#define ALLKEYS(x) x##1, x##2, x##3, x##4
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2, KEY3TYPE x##3, KEY4TYPE x##4
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);KEY3CPY(m);KEY4CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2) && KEY3_EQ_P(m->key3,key3)\
		&& KEY4_EQ_P(m->key4,key4))
#elif KEY_ARITY == 5
#define KEYSYM(x) JOIN6(x,KEY1N,KEY2N,KEY3N,KEY4N,KEY5N,VALN)
#define ALLKEYS(x) x##1, x##2, x##3, x##4, x##5
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2, KEY3TYPE x##3, KEY4TYPE x##4, KEY5TYPE x##5
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);KEY3CPY(m);KEY4CPY(m);KEY5CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2) && KEY3_EQ_P(m->key3,key3)\
		&& KEY4_EQ_P(m->key4,key4) && KEY5_EQ_P(m->key5,key5))
#elif KEY_ARITY == 6
#define KEYSYM(x) JOIN7(x,KEY1N,KEY2N,KEY3N,KEY4N,KEY5N,KEY6N,VALN)
#define ALLKEYS(x) x##1, x##2, x##3, x##4, x##5, x##6
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2, KEY3TYPE x##3, KEY4TYPE x##4, KEY5TYPE x##5, KEY6TYPE x##6
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);KEY3CPY(m);KEY4CPY(m);KEY5CPY(m);KEY6CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2) && KEY3_EQ_P(m->key3,key3)\
		&& KEY4_EQ_P(m->key4,key4) && KEY5_EQ_P(m->key5,key5) && KEY6_EQ_P(m->key6,key6))
#elif KEY_ARITY == 7
#define KEYSYM(x) JOIN8(x,KEY1N,KEY2N,KEY3N,KEY4N,KEY5N,KEY6N,KEY7N,VALN)
#define ALLKEYS(x) x##1, x##2, x##3, x##4, x##5, x##6, x##7
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2, KEY3TYPE x##3, KEY4TYPE x##4, KEY5TYPE x##5, KEY6TYPE x##6, KEY7TYPE x##7
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);KEY3CPY(m);KEY4CPY(m);KEY5CPY(m);KEY6CPY(m);KEY7CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2) && KEY3_EQ_P(m->key3,key3)\
		&& KEY4_EQ_P(m->key4,key4) && KEY5_EQ_P(m->key5,key5) && KEY6_EQ_P(m->key6,key6)\
		&& KEY7_EQ_P(m->key7,key7))
#elif KEY_ARITY == 8
#define KEYSYM(x) JOIN9(x,KEY1N,KEY2N,KEY3N,KEY4N,KEY5N,KEY6N,KEY7N,KEY8N,VALN)
#define ALLKEYS(x) x##1, x##2, x##3, x##4, x##5, x##6, x##7, x##8
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2, KEY3TYPE x##3, KEY4TYPE x##4, KEY5TYPE x##5, KEY6TYPE x##6, KEY7TYPE x##7, KEY8TYPE x##8
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);KEY3CPY(m);KEY4CPY(m);KEY5CPY(m);KEY6CPY(m);KEY7CPY(m);KEY8CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2) && KEY3_EQ_P(m->key3,key3)\
		&& KEY4_EQ_P(m->key4,key4) && KEY5_EQ_P(m->key5,key5) && KEY6_EQ_P(m->key6,key6)\
		&& KEY7_EQ_P(m->key7,key7) && KEY8_EQ_P(m->key8,key8))
#elif KEY_ARITY == 9
#define KEYSYM(x) JOIN10(x,KEY1N,KEY2N,KEY3N,KEY4N,KEY5N,KEY6N,KEY7N,KEY8N,KEY9N,VALN)
#define ALLKEYS(x) x##1, x##2, x##3, x##4, x##5, x##6, x##7, x##8, x##9
#define ALLKEYSD(x) KEY1TYPE x##1, KEY2TYPE x##2, KEY3TYPE x##3, KEY4TYPE x##4, KEY5TYPE x##5, KEY6TYPE x##6, KEY7TYPE x##7, KEY8TYPE x##8, KEY9TYPE x##9
#define KEYCPY(m) {KEY1CPY(m);KEY2CPY(m);KEY3CPY(m);KEY4CPY(m);KEY5CPY(m);KEY6CPY(m);KEY7CPY(m);KEY8CPY(m);KEY9CPY(m);}
#define KEY_EQ_P(m) (KEY1_EQ_P(m->key1,key1) && KEY2_EQ_P(m->key2,key2) && KEY3_EQ_P(m->key3,key3)\
		&& KEY4_EQ_P(m->key4,key4) && KEY5_EQ_P(m->key5,key5) && KEY6_EQ_P(m->key6,key6)\
		&& KEY7_EQ_P(m->key7,key7) && KEY8_EQ_P(m->key8,key8) && KEY9_EQ_P(m->key9,key9))
#endif

/* */

struct KEYSYM(map_node) {
	/* common node bits */
	struct map_node node;

	KEY1STOR;
#if KEY_ARITY > 1
	KEY2STOR;
#if KEY_ARITY > 2
	KEY3STOR;
#if KEY_ARITY > 3
	KEY4STOR;
#if KEY_ARITY > 4
	KEY5STOR;
#if KEY_ARITY > 5
	KEY6STOR;
#if KEY_ARITY > 6
	KEY7STOR;
#if KEY_ARITY > 7
	KEY8STOR;
#if KEY_ARITY > 8
	KEY9STOR;
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif

	VALSTOR;
	/* NB: the value must be last, because in the case of
	 * stat_data we dynamically size its histogram[].  */
};

static inline struct KEYSYM(map_node)*
KEYSYM(get_map_node) (struct map_node* m)
{
	return container_of(m, struct KEYSYM(map_node), node);
}

#define type_to_enum(type)						\
	({								\
		int ret;						\
		if (__builtin_types_compatible_p (type, char*))		\
			ret = STRING;					\
		else							\
			ret = INT64;					\
		ret;							\
	})

static key_data KEYSYM(map_get_key) (struct map_node *mn, int n, int *type)
{
	key_data ptr;
	struct KEYSYM(map_node) *m = KEYSYM(get_map_node)(mn);

	if (n < 1) {
		if (type)
			*type = VALUE_TYPE;
		return (key_data)MAP_GET_VAL(m);
	}

	if (n > KEY_ARITY) {
		if (type)
			*type = END;
		return (key_data)(int64_t)0;
	}

	switch (n) {
	case 1:
		ptr = (key_data)m->key1;
		if (type)
			*type = type_to_enum(KEY1TYPE);
		break;
#if KEY_ARITY > 1
	case 2:
		ptr = (key_data)m->key2;
		if (type)
			*type = type_to_enum(KEY2TYPE);

		break;
#if KEY_ARITY > 2
	case 3:
		ptr = (key_data)m->key3;
		if (type)
			*type = type_to_enum(KEY3TYPE);
		break;
#if KEY_ARITY > 3
	case 4:
		ptr = (key_data)m->key4;
		if (type)
			*type = type_to_enum(KEY4TYPE);
		break;
#if KEY_ARITY > 4
	case 5:
		ptr = (key_data)m->key5;
		if (type)
			*type = type_to_enum(KEY5TYPE);
		break;
#if KEY_ARITY > 5
	case 6:
		ptr = (key_data)m->key6;
		if (type)
			*type = type_to_enum(KEY6TYPE);
		break;
#if KEY_ARITY > 6
	case 7:
		ptr = (key_data)m->key7;
		if (type)
			*type = type_to_enum(KEY7TYPE);
		break;
#if KEY_ARITY > 7
	case 8:
		ptr = (key_data)m->key8;
		if (type)
			*type = type_to_enum(KEY8TYPE);
		break;
#if KEY_ARITY > 8
	case 9:
		ptr = (key_data)m->key9;
		if (type)
			*type = type_to_enum(KEY9TYPE);
		break;
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
	default:
		ptr = (key_data)(int64_t)0;
		if (type)
			*type = END;
	}
	return ptr;
}

/** Return an int64 key from a map node.
 * This function will return an int64 key from a map_node.
 * @param mn pointer to the map_node.
 * @param n key number
 * @returns an int64
 */
static int64_t KEYSYM(_stp_map_key_get_int64) (struct map_node *mn, int n)
{
	int type;
	int64_t res = 0;
	if (mn) {
		res = KEYSYM(map_get_key)(mn, n, &type).val;
		if (type != INT64)
			res = 0;
	}
	return res;
}

/** Return a string key from a map node.
 * This function will return an string key from a map_node.
 * @param mn pointer to the map_node.
 * @param n key number
 * @returns a pointer to a string
 */
static char *KEYSYM(_stp_map_key_get_str) (struct map_node *mn, int n)
{
	int type;
	char *str = "";
	if (mn) {
		str = KEYSYM(map_get_key)(mn, n, &type).strp;
		if (type != STRING)
			str = "bad type";
	}
	return str;
}

/** Return value from a map node.
 * This function will return the int64/str/stat value of a map_node.
 * @param m pointer to the map_node. 
 * @returns a typed value.
 */
static VALTYPE KEYSYM(JOIN(_stp_map_get,VALNAME))(struct map_node *m)
{
	return m ? MAP_GET_VAL(KEYSYM(get_map_node)(m)) : 0;
}

static void KEYSYM(_stp_map_sort) (MAP map, int keynum, int dir)
{
	_stp_map_sort (map, keynum, dir, KEYSYM(map_get_key));
}

static void KEYSYM(_stp_map_sortn) (MAP map, int n, int keynum, int dir)
{
	_stp_map_sortn (map, n, keynum, dir, KEYSYM(map_get_key));
}


static unsigned int KEYSYM(keycheck) (ALLKEYSD(key))
{
#if KEY1_TYPE == STRING
	if (key1 == NULL)
		return 0;
#endif

#if KEY_ARITY > 1
#if KEY2_TYPE == STRING
	if (key2 == NULL)
		return 0;
#endif

#if KEY_ARITY > 2
#if KEY3_TYPE == STRING
	if (key3 == NULL)
		return 0;
#endif

#if KEY_ARITY > 3
#if KEY4_TYPE == STRING
	if (key4 == NULL)
		return 0;
#endif

#if KEY_ARITY > 4
#if KEY5_TYPE == STRING
	if (key5 == NULL)
		return 0;
#endif

#if KEY_ARITY > 5
#if KEY6_TYPE == STRING
	if (key6 == NULL)
		return 0;
#endif

#if KEY_ARITY > 6
#if KEY7_TYPE == STRING
	if (key7 == NULL)
		return 0;
#endif

#if KEY_ARITY > 7
#if KEY8_TYPE == STRING
	if (key8 == NULL)
		return 0;
#endif

#if KEY_ARITY > 8
#if KEY9_TYPE == STRING
	if (key9 == NULL)
		return 0;
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
	return 1;
}

static uint32_t KEYSYM(hash) (ALLKEYSD(key)) /* NB: unscaled! */
{
        /* Open-code 32-bit murmurhash3 */
        uint32_t len = 0;
        uint32_t h1 = stap_hash_seed;
        const uint32_t c1 = 0xcc9e2d51;
        const uint32_t c2 = 0x1b873593;
        KEY1_HASH;
#if KEY_ARITY > 1
        KEY2_HASH;
#if KEY_ARITY > 2
        KEY3_HASH;
#if KEY_ARITY > 3
        KEY4_HASH;
#if KEY_ARITY > 4
        KEY5_HASH;
#if KEY_ARITY > 5
        KEY6_HASH;
#if KEY_ARITY > 6
        KEY7_HASH;
#if KEY_ARITY > 7
        KEY8_HASH;
#if KEY_ARITY > 8
        KEY9_HASH;
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif

        // finalization
        h1 ^= len;
        // fmix32
        h1 ^= h1 >> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >> 16;

        return h1;
}


#if VALUE_TYPE == INT64 || VALUE_TYPE == STRING
static MAP KEYSYM(_stp_map_new) (unsigned max_entries, int wrap)
{
	MAP m = _stp_map_new (max_entries, wrap,
			      sizeof(struct KEYSYM(map_node)), -1);
	return m;
}
#else

/*
 * _stp_map_new_key1_key2...val (num, wrap, HIST_LINEAR, start, end, interval)
 * _stp_map_new_key1_key2...val (num, wrap, HIST_LOG)
 */ 
static MAP KEYSYM(_stp_map_new) (unsigned max_entries, int wrap, int htype, ...)
{
	int start=0, stop=0, interval=0;
	MAP m;

	if (htype == HIST_LINEAR) {
		va_list ap;
		va_start (ap, htype);
		start = va_arg(ap, int);
		stop = va_arg(ap, int);
		interval = va_arg(ap, int);
		va_end (ap);
	}

	switch (htype) {
	case HIST_NONE:
		m = _stp_map_new_hstat (max_entries, wrap,
					sizeof(struct KEYSYM(map_node)));
		break;
	case HIST_LOG:
		m = _stp_map_new_hstat_log (max_entries, wrap,
					    sizeof(struct KEYSYM(map_node)));
		break;
	case HIST_LINEAR:
		m = _stp_map_new_hstat_linear (max_entries, wrap,
					       sizeof(struct KEYSYM(map_node)),
					       start, stop, interval);
		break;
	default:
		_stp_warn ("Unknown histogram type %d\n", htype);
		m = NULL;
	}

	return m;
}

#endif /* VALUE_TYPE */

static int KEYSYM(__stp_map_set) (MAP map, ALLKEYSD(key), VSTYPE val, int add)
{
	unsigned int hv;
	struct mhlist_head *head;
	struct mhlist_node *e;
	struct KEYSYM(map_node) *n;

	if (map == NULL)
		return -2;

	if (KEYSYM(keycheck) (ALLKEYS(key)) == 0)
		return -2;

	hv = KEYSYM(hash) (ALLKEYS(key)) & map->hash_table_mask;
	head = &map->hashes[hv];

	mhlist_for_each_entry(n, e, head, node.hnode) {
		if (KEY_EQ_P(n)) {
			return MAP_SET_VAL(map, n, val, add);
		}
	}
	/* key not found */
	n = KEYSYM(get_map_node)(_new_map_create (map, head));
	if (n == NULL)
		return -1;
	KEYCPY(n);
	return MAP_SET_VAL(map, n, val, 0);
}

static int KEYSYM(_stp_map_set) (MAP map, ALLKEYSD(key), VSTYPE val)
{
	return KEYSYM(__stp_map_set) (map, ALLKEYS(key), val, 0);
}

static int KEYSYM(_stp_map_add) (MAP map, ALLKEYSD(key), VSTYPE val)
{
	return KEYSYM(__stp_map_set) (map, ALLKEYS(key), val, 1);
}


static VALTYPE KEYSYM(_stp_map_get) (MAP map, ALLKEYSD(key))
{
	unsigned int hv;
	struct mhlist_head *head;
	struct mhlist_node *e;
	struct KEYSYM(map_node) *n;

	if (map == NULL)
		return NULLRET;

	hv = KEYSYM(hash) (ALLKEYS(key)) & map->hash_table_mask;
	head = &map->hashes[hv];

	mhlist_for_each_entry(n, e, head, node.hnode) {
		if (KEY_EQ_P(n)) {
			return MAP_GET_VAL(n);
		}
	}
	/* key not found */
	return NULLRET;
}

static int KEYSYM(_stp_map_del) (MAP map, ALLKEYSD(key))
{
	unsigned int hv;
	struct mhlist_head *head;
	struct mhlist_node *e;
	struct KEYSYM(map_node) *n;

	if (map == NULL)
		return -1;

	if (KEYSYM(keycheck) (ALLKEYS(key)) == 0)
		return -1;

	hv = KEYSYM(hash) (ALLKEYS(key)) & map->hash_table_mask;
	head = &map->hashes[hv];

	mhlist_for_each_entry(n, e, head, node.hnode) {
		if (KEY_EQ_P(n)) {
			_new_map_del_node(map, &n->node);
			return 0;
		}
	}
	/* key not found */
	return 0;
}

static int KEYSYM(_stp_map_del_hash) (MAP map, unsigned int hv /* scaled */,
                                      ALLKEYSD(key))
{
	struct mhlist_head *head;
	struct mhlist_node *e;
	struct KEYSYM(map_node) *n;

	if (map == NULL)
		return -1;

	head = &map->hashes[hv];
	mhlist_for_each_entry(n, e, head, node.hnode) {
		if (KEY_EQ_P(n)) {
			_new_map_del_node(map, &n->node);
			return 0;
		}
	}
	/* key not found */
	return 0;
}

static int KEYSYM(_stp_map_exists) (MAP map, ALLKEYSD(key))
{
	unsigned int hv;
	struct mhlist_head *head;
	struct mhlist_node *e;
	struct KEYSYM(map_node) *n;

	if (map == NULL)
		return 0;

	hv = KEYSYM(hash) (ALLKEYS(key)) & map->hash_table_mask;
	head = &map->hashes[hv];

	mhlist_for_each_entry(n, e, head, node.hnode) {
		if (KEY_EQ_P(n)) {
			return 1;
		}
	}
	/* key not found */
	return 0;
}


/* Pull in pmaps while all the defines are still in place.  */
#ifdef MAP_DO_PMAP
#include "pmap-gen.c"
#endif


#undef KEY1NAME
#undef KEY1N
#undef KEY1TYPE
#undef KEY1_TYPE
#undef KEY1STOR
#undef KEY1CPY
#undef KEY1_HASH

#undef KEY2NAME
#undef KEY2N
#undef KEY2TYPE
#undef KEY2_TYPE
#undef KEY2STOR
#undef KEY2CPY
#undef KEY2_HASH

#undef KEY3NAME
#undef KEY3N
#undef KEY3TYPE
#undef KEY3_TYPE
#undef KEY3STOR
#undef KEY3CPY
#undef KEY3_HASH

#undef KEY4NAME
#undef KEY4N
#undef KEY4TYPE
#undef KEY4_TYPE
#undef KEY4STOR
#undef KEY4CPY
#undef KEY4_HASH

#undef KEY5NAME
#undef KEY5N
#undef KEY5TYPE
#undef KEY5_TYPE
#undef KEY5STOR
#undef KEY5CPY
#undef KEY5_HASH

#undef KEY6NAME
#undef KEY6N
#undef KEY6TYPE
#undef KEY6_TYPE
#undef KEY6STOR
#undef KEY6CPY
#undef KEY6_HASH

#undef KEY7NAME
#undef KEY7N
#undef KEY7TYPE
#undef KEY7_TYPE
#undef KEY7STOR
#undef KEY7CPY
#undef KEY7_HASH

#undef KEY8NAME
#undef KEY8N
#undef KEY8TYPE
#undef KEY8_TYPE
#undef KEY8STOR
#undef KEY8CPY
#undef KEY8_HASH

#undef KEY9NAME
#undef KEY9N
#undef KEY9TYPE
#undef KEY9_TYPE
#undef KEY9STOR
#undef KEY9CPY
#undef KEY9_HASH

#undef KEY_ARITY
#undef ALLKEYS
#undef ALLKEYSD
#undef KEYCPY
#undef KEYSYM
#undef KEY_EQ_P

#undef VALUE_TYPE
#undef VALNAME
#undef VALTYPE
#undef VSTYPE
#undef VALN
#undef VALSTOR

#undef MAP_COPY_VAL
#undef MAP_SET_VAL
#undef MAP_GET_VAL
#undef NULLRET
