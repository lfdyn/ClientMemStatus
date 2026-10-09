# Reversing Roblox ClientBlockedImage and ClientMemStatus

**Build:** `version-cec3ad5889b447cf`

## Why I started looking at this

I've been getting more into reversing the Roblox client recently, and I wanted to figure out where some of its DLL checks actually go. I started with a log string called `ClientBlockedImage` and followed the references in IDA. That eventually led me into the telemetry code and a separate record parser called `ClientMemStatus`.

The interesting part is that I couldn't find anything in the static code that actually adds names to the set `ClientBlockedImage` searches. At first I was ready to call it dead code, but that needs a little more care. The protected parts of the client could be doing something I can't see in this dump. This post is about what I found, what I got wrong along the way, and what I still can't confirm.

I'm not claiming to be an expert here. I'm keeping the addresses and some decompiler output because they're what helped me check my own assumptions.

## First, what is ClientBlockedImage?

The question it seems to ask is pretty straightforward: is a recently loaded DLL name in a blocked-name set?

Windows raises a loader notification whenever an image is mapped into the process. Roblox subscribes to that, takes the module name, and checks it against a set of names it considers disallowed. If the name matches, it reports it.

That is the entire feature. It is a name lookup. There is no hashing, no PE header validation, no section comparison, no behaviour analysis. If this were the only control standing between the client and an injected module, it would be trivially defeated by renaming the module.

## Why the check exists

The purpose is to catch the lazy case. An injector that drops a DLL with an obvious name into the process gets caught at load time, before anything else runs, and the report goes back over the wire so the server can act on it.

That report is the point of the whole feature. The check itself is cheap; the telemetry it emits on a match is what matters to the enforcement pipeline. So when you read the code, the thing to track is not the string compare - it is where the string compare's result goes.

## How it fits with the other telemetry

`ClientBlockedImage` is one of a family of client-side detectors that all report through the same counter/telemetry path. The reason I reversed it was to map that path, because the same path carries the detection flags that surface on the network side (the `PingItem` detection word). The two are different surfaces for the same enforcement system: local checks that report upward, and a network protocol that reports downward.

## Finding the strings in IDA

I scanned `.rdata` for every string containing `block`. 36 hits, most of them unrelated settings `BlockedRequestsRate`, `BlockedHundredthsPercentage`, `BlockedUniverseIds`, `BlockedLanguage`.

Roblox has a lot of "blocked" things that are just FVariables.

These were the two strings that caught my attention:

`0x7181520`: `ClientBlockedImage`.

`0x7181600`: `[DFLog::ClientBlockedImage] Blocked DLL: {}`.

`0x7181520` resolves through `dq offset aClientblockedi` at `0x7E51F80` into `sub_4E2A660`, which

is a 29-byte FLog channel registration:

```c

void RegisterClientBlockedImageChannel(void)

{

  sub_4991AD0(

    qword_8A927F8,

    "ClientBlockedImage",

    &qword_7E51F78,

    2

  );

}

```
Two things worth noting there. `qword_7E51F78` is the channel's verbosity word - the detector checks it before printing, which is why the log line is invisible at normal verbosity. And the `2` is the number of format arguments the channel's strings take.

## Following the calls

`ClientBlockedImage` is not a scanner and it is not a callback on a timer. It is a subscriber to the loader image-notification broadcast.

```

loader notification

  -> pfnwk @ 0x4E2AE7F            walks the global Hyperion callback list

     -> sub_4E2B330               builds a std::wstring, packs a closure

        -> sub_4E310C0            EnterCriticalSection + invoke all handlers

           -> sub_4E2AB90         gets the ctx singleton, converts wide -> narrow

              -> sub_4E2E340      the detector

                 -> sub_4E2E740   event #14 payload build

                    -> CFG-guarded virtual call @ vtable+0x30

```
After that I went through the functions one at a time.

### `sub_4E2B330` - the fanout entry

Takes the raw wide string from the loader, wraps it, and hands it to the broadcast. Note the `Src != nullptr` guard and the manual `wcslen` - MSVC will not do this for you on a raw pointer.

```c

__int64 __fastcall sub_4E2B330(_WORD *Src, char a2)

{

  __int64 v2;

  unsigned __int8 v3;

  unsigned __int8 v4;

  __int64 v5;

  _BYTE v7[8];

  __int64 (__fastcall *v8)(_QWORD *, unsigned __int8);

  _QWORD v9[3];

  unsigned __int64 v10;

  v7[0] = a2;

  v10 = 7;

  v9[0] = 0;

  v9[2] = 0;

  if ( Src != nullptr )

  {

    v2 = -1;

    do

      ++v2;

    while ( Src[v2] != 0 );

    sub_7226A0(v9, Src);

  }

  v8 = sub_4E2AB90;

  v3 = sub_4E310C0(&v8, v9, v7);

  v4 = v3;

  if ( v10 >= 8 )

  {

    v5 = v9[0];

    if ( 2 * v10 + 2 >= 0x1000 )

    {

      v5 = *(_QWORD *)(v9[0] - 8LL);

      if ( (unsigned __int64)(v9[0] - v5 - 8) > 0x1F )

        invalid_parameter_noinfo_noreturn();

    }

    sub_495A1C0(v5, v5);

  }

  return v4;

}

```
The closure is a single `__int64 (__fastcall *)(_QWORD *, unsigned __int8)` - a function pointer taking the wstring and the bool. `sub_4E310C0` takes that closure, the wstring, and the flag.

### `sub_4E310C0` - the broadcast

```c

__int64 __fastcall sub_4E310C0(void *closure, __int64 *name, _BYTE *flag)

{

  ...

  EnterCriticalSection(stru_8BE60B0);

  registered = qword_8BE60F0;

  if ( registered )

  {

    do {

      refcount_obj = registered->ctrl;

      if ( refcount_obj )

      {

        do {

          old = InterlockedCompareExchange(&refcount_obj->strong, refcount_obj->strong + 1, refcount_obj->strong);

        } while ( old != refcount_obj->strong );

      }

      entry = registered->first;

    } while ( ... );

    if ( entry->second )

      entry = (entry->second)(entry, name, flag);

  }

  LeaveCriticalSection(stru_8BE60B0);

  ...

}

```
Reconstructed from the disassembly at `0x4E310C0` - `off_6183D58` is `EnterCriticalSection`, `off_6183D28` is `LeaveCriticalSection`, `qword_8BE60F0` is the handler-list anchor, and the `lock cmpxchg` loop is the shared_ptr strong-refcount acquisition. Every registered handler gets invoked with the same `(name, flag)` pair.

### `sub_4E2AB90` - the handler

```c

__int64 __fastcall sub_4E2AB90(_QWORD *a1, unsigned __int8 a2)

{

  char *v4;

  _QWORD *v5;

  _QWORD *v6;

  unsigned __int8 v7;

  __int64 v8;

  __int64 v10[2];

  void *v11;

  _QWORD v12[2];

  __int64 v13;

  unsigned __int64 v14;

  v11 = a1;

  v4 = (char *)sub_4E2E120();

  v5 = a1;

  if ( a1[3] >= 8u )

    v5 = (_QWORD *)*a1;

  sub_496F2E0(v12, v5, a1[2]);

  v6 = v12;

  if ( v14 >= 0x10 )

    v6 = (_QWORD *)v12[0];

  v10[0] = (__int64)v6;

  v10[1] = v13;

  v7 = sub_4E2E340(v4, v10, a2);

  ...

  sub_722620(a1);

  return v7;

}

```
Three things: `sub_4E2E120()` fetches the ctx singleton. The `a1[3] >= 8` / `v14 >= 0x10` checks are SSO branches on the `std::wstring` and `std::string` respectively. And `sub_496F2E0` is the wide-to-narrow conversion - which is where a non-ASCII module name would already break.

### `sub_4E2E120` - the ctx singleton

```c

void *sub_4E2E120()

{

  if ( dword_8BE60FC <= *(_DWORD *)(*(_QWORD *)NtCurrentTeb()->ThreadLocalStoragePointer + 32LL) )

    return &unk_7E81F78;

  sub_1270(&dword_8BE60FC);

  if ( dword_8BE60FC != -1 )

    return &unk_7E81F78;

  atexit(sub_616F1A0);

  sub_1350(&dword_8BE60FC);

  return &unk_7E81F78;

}

```
A thread-safe static local. `unk_7E81F78` is the shared context object; the byte at `+0x10` is the feature-enable flag.

### `sub_4E2E340` - the detector

This is the whole predicate. `a1` is the ctx, `a2` the name, `a3` the caller's default result.

```c

__int64 __fastcall sub_4E2E340(char *a1, __int64 *a2, unsigned __int8 a3)

{

  int v3;

  unsigned __int8 v6;

  __int64 v7;

  __int64 v8;

  __int64 v9;

  char v10;

  char v11;

  _QWORD *v12;

  __int64 *ThreadLocalStoragePointer;

  __int64 v14;

  __int64 v15;

  __int64 v16;

  __int64 v17;

  __int64 v18;

  __int64 v19;

  _QWORD *v20;

  char v21;

  __int64 v22;

  __int64 v23;

  __int64 v24;

  __int64 v25;

  __int64 v26;

  __int64 v27;

  int *v29;

  _QWORD v30[2];

  _QWORD v31[2];

  void *v32;

  char v33;

  _BYTE v34[16];

  __int128 v35;

  _QWORD v36[3];

  unsigned __int64 v37;

  _QWORD v38[2];

  __int64 v39[2];

  __int64 v40;

  unsigned __int64 v41;

  __int64 v42[3];

  unsigned __int64 v43;

  v3 = a3;

  if ( a1[16] == 0 )

    return a3 ^ 1u;

  v7 = a2[1];

  sub_720D10(v36, v7, 0);

  v8 = 0;

  if ( v7 != 0 )

  {

    v9 = *a2;

    do

    {

      v10 = *(_BYTE *)(v9 + v8);

      v11 = v10 + 32;

      if ( (unsigned __int8)(v10 - 65) > 0x19u )

        v11 = *(_BYTE *)(v9 + v8);

      v12 = v36;

      if ( v37 >= 0x10 )

        v12 = (_QWORD *)v36[0];

      *((_BYTE *)v12 + v8++) = v11;

    }

    while ( v8 != v7 );

  }

  ThreadLocalStoragePointer = (__int64 *)NtCurrentTeb()->ThreadLocalStoragePointer;

  v14 = *ThreadLocalStoragePointer;

  if ( dword_8BE6100 > *(_DWORD *)(*ThreadLocalStoragePointer + 32) )

  {

    if ( sub_1270(&dword_8BE6100), dword_8BE6100 == -1 )

    {

      LODWORD(v29) = 0;

      sub_721D00(&unk_8BE6110, &v29);

      atexit(sub_616F1C0);

      sub_1350(&dword_8BE6100);

    }

  }

  if ( dword_8BE6150 > *(_DWORD *)(v14 + 32) )

  {

    sub_1270(&dword_8BE6150);

    if ( dword_8BE6150 == -1 )

    {

      sub_8BA0(&unk_8BE6158, "TrackedImagesGuard", 0);

      xmmword_8BE6160 = 0;

      atexit(sub_616F1B0);

      sub_1350(&dword_8BE6150);

    }

  }

  v32 = &unk_8BE6158;

  v33 = 1;

  v15 = sub_6D90();

  if ( v15 == (_QWORD)xmmword_8BE6160 )

  {

    ++*((_QWORD *)&xmmword_8BE6160 + 1);

    sub_729F50(&unk_8BE6110, v34, v36);

  }

  else

  {

    sub_89F0(&unk_8BE6158, 0);

    *(_QWORD *)&xmmword_8BE6160 = v15;

    ++*((_QWORD *)&xmmword_8BE6160 + 1);

    sub_729F50(&unk_8BE6110, v34, v36);

  }

  if ( --*((_QWORD *)&xmmword_8BE6160 + 1) == 0 )

  {

    *(_QWORD *)&xmmword_8BE6160 = 0;

    sub_8B30(&unk_8BE6158);

  }

  if ( v34[8] != 0 )

  {

    if ( (unsigned __int8)qword_7E51F78 >= 6u && BYTE1(qword_7E51F78) >= 2u )

    {

      v29 = &dword_7450200;

      v31[0] = "[DFLog::ClientBlockedImage] Blocked DLL: {}";

      v19 = -1;

      do

        ++v19;

      while ( aDflogClientblo[v19] != 0 );

      v31[1] = v19;

      v20 = v36;

      if ( v37 >= 0x10 )

        v20 = (_QWORD *)v36[0];

      v38[0] = v20;

      v38[1] = v36[2];

      v30[0] = 13;

      v30[1] = v38;

      v35 = *(_OWORD *)&qword_7E51F78;

      LOBYTE(v16) = 2;

      sub_49759D0((unsigned int)&v35, v16, (unsigned int)v31, (unsigned int)v30, 1);

    }

    sub_4E3ABA0(4053620476LL, v16, v17, v18);

    v21 = *a1;

    v42[0] = 0;

    v43 = 15;

    v42[2] = 0;

    v39[0] = 0;

    v41 = 15;

    v40 = 0;

    sub_4E2E740((int)a1, 14, v3, 0, v36, (__int64)v39, (__int64)v42, v21);

  }

  v6 = v3 ^ 1;

  if ( v37 >= 0x10 )

  {

    v26 = v36[0];

    v27 = v36[0];

    if ( v37 + 1 >= 0x1000 )

    {

      v26 = *(_QWORD *)(v36[0] - 8LL);

      v27 = v36[0] - v26;

      if ( (unsigned __int64)(v36[0] - v26 - 8) > 0x1F )

        invalid_parameter_noinfo_noreturn();

    }

    sub_495A1C0(v26, v27);

  }

  return v6;

}

```
Reading the important parts:

****The feature gate**** is `if ( a1[16] == 0 ) return a3 ^ 1u;`. If the ctx's byte at `+0x10` is zero, the detector does no work at all and immediately returns the inverted input flag. This is the cheapest possible off switch for the entire feature.

****The name normalisation**** is an inlined `tolower`:

```

v11 = c + 0x20;

if ( (unsigned __int8)(c - 65) > 0x19u )

  v11 = c;

```
That is the exact MSVC pattern. There is no hashing step in front of it, and no comparison of anything but the resulting string.

****The lookup**** is `sub_729F50(&unk_8BE6110, v34, v36)` - `unordered_set::find(&out_iterator, &needle)`. The `xmmword_8BE6160` counter and `unk_8BE6158` mutex are the compiler's thread-safe-static-lazy-init machinery for the global, plus a reader-count so concurrent lookups are safe.

****The hit test**** is `if ( v34[8] != 0 )`. `v34` is the out-iterator; byte 8 is its discriminator, non-zero meaning "found".

****On a hit****, three things happen in order:

1\. If `qword_7E51F78` byte 0 is at least 6 and byte 1 at least 2, emit the DFLog line.

2\. `sub_4E3ABA0(0xF19D56FC)` - the server-bound counter.

3\. `sub_4E2E740(ctx, 14, flag, 0, name, s1, s0)` - event #14.

****The return value is `v3 ^ 1` on every path.**** Gate off, gate on and miss, gate on and hit - all three return `!flag`. The boolean is not the answer. The decision is entirely in the side effects, which is a slightly unusual and easy-to-misread structure.

### `sub_4E3ABA0` - the event counter

```c

__int64 __fastcall sub_4E3ABA0(__int64 a1, __int64 a2, __int64 a3, __int64 a4)

{

  _QWORD v6[2];

  _BYTE v7[40];

  _BYTE v8[680];

  _BYTE v9[8];

  _BYTE v10[56];

  sub_70E630(v7, &off_7E52210, a3, a4);

  v6[0] = "event";

  v6[1] = 5;

  sub_2E00B00(v9, v6, a1, 1);

  sub_2DF2BF0(v10);

  sub_70E440(v9);

  return sub_722920(v8);

}

```
`off_7E52210` is the counter name (`QevtCounter`), the key is `"event"`, and `a1` is

`0xF19D56FC`. This is the report that leaves the client.

## The empty blocklist question

`unk_8BE6110` is the `std::unordered_set<std::string>` that `sub_4E2E340` searches. Here is the complete reference set, taken with `XrefsTo()` over the object and both of its neighbours:

`sub_4E2E340+0x360` (`sub_721D00`): magic-static ****default construct****.

`sub_4E2E340+0x108` (`sub_729F50`): ****`find()`**** - read only.

`sub_616F1C0` (`sub_71F610` / `sub_71FAA0`): atexit destructor on `unk_8BE6118` / `unk_8BE6128`.

There is no fourth reference. There is no `insert`, no `emplace`, no `operator[]`, no `try_emplace`. The decompiled function shows this directly - the only calls touching `unk_8BE6110` are the default-construct inside the init guard and the `find`.

The destructor is the decisive evidence. `sub_616F1C0`:

```c

void sub_616F1C0(void)

{

  sub_71F610(&unk_8BE6128);

  sub_71FAA0(&unk_8BE6118);

}

```
It touches only the **second** and **third** members of the object and does nothing to the first.

That is exactly the shape of `\~unordered_set`, which releases the bucket array and the end node after the container's head has already been torn down. An inserting function would have to build a node and splice it, and no code in the binary does that.

I also ran a full-binary scan for a static source list - `denylist`, `BlockedDll`, `BlockedImageList`, `BlockedModules`, `BlockedDlls`. Zero hits beyond the FLog channel names.

****Conclusion.**** In this build, `unk_8BE6110` is born empty, searched once, and destroyed. The `find()` in `sub_4E2E340` always returns `end()`. The entire hit branch - DFLog line, counter, event #14, the CFG-guarded send - is reachable code with no reachable input. I could not confirm that it fires in this static view.

The set has to be populated at runtime from outside this module. The only runtime-dynamic code in the binary is the Hyperion band, which is decrypted and relocated at load:

`tempest` (`0x9125000 - 0x9126000`): Hyperion entry.

`.byfron` (`0x9126000 - 0x9127000`): Hyperion core.

`.impfix` (`0x9127000 - 0x9130000`): import verification.

`.imptrmp` (`0x9130000 - 0x9132000`): import trampolines.

`.relfix` (`0x9132000 - 0x9245000`): relocation fixups.

So the blocklist contents are not statically readable. That is a fact about the binary, not an obstacle to work around.

## Something I got wrong the first time

In a first pass I wrote that `sub_4E31640`, `sub_4E318C0` and `sub_4E31B50` were the code that populates the blocklist. That was wrong, and the evidence is unambiguous once you look at the vtable they install.

`sub_4E31640` at `0x4E31727`:

```asm

lea  rax, ??_7?$_Ref_count_obj_alloc3@VCallbackListEntry@Hyperion@@V?$Allocator@VCallbackListEntry@Hyperion@@RSL@@@@@std@@6B@

mov  [r14], rax

```
and at `0x4E317B5`:

```asm

lea  rax, ??_7?$_Ref_count_obj2@VCallbackListEntry@Hyperion@@@std@@6B@

mov  [r14], rax

```
These are `Hyperion::CallbackListEntry`, ref-counted, custom-allocated. Not a set. Not a scanner.

Here is the function:

```c

__int64 *__fastcall sub_4E31640(__int64 a1, __int64 *a2, _QWORD *a3, _DWORD *a4, _OWORD *a5)

{

  __int64 v8;

  __int64 v9;

  _OWORD *v10;

  __int64 v11;

  __int64 v12;

  __int64 v13;

  __int64 v14;

  __int64 v15;

  __int64 v16;

  PSLIST_ENTRY v17;

  __int64 v18;

  __int64 v19;

  struct _SLIST_ENTRY *Next;

  __int64 *result;

  _QWORD pExceptionObject[5];

  __int64 v23;

  void *v24;

  v24 = a2;

  v23 = a1;

  v8 = sub_495A700(48);

  v9 = v8;

  if ( v8 == 0 )

  {

    sub_6F4C20(pExceptionObject);

    throw (std::bad_alloc *)pExceptionObject;

  }

  *(_QWORD *)v8 = 0;

  *(_QWORD *)(v8 + 16) = 0;

  *(_QWORD *)(v8 + 24) = 0;

  v10 = a5;

  *(_OWORD *)v8 = *a5;

  *(_OWORD *)(v8 + 16) = v10[1];

  *((_QWORD *)v10 + 2) = 0;

  *((_QWORD *)v10 + 3) = 7;

  *(_WORD *)v10 = 0;

  *(_DWORD *)(v8 + 32) = *a4;

  *(_QWORD *)(v8 + 40) = *a3;

  a5 = (_OWORD *)v8;

  *a2 = 0;

  a2[1] = 0;

  if ( byte_829C78C != 0 )

  {

    v11 = sub_2F32090();

    v12 = v11;

    v23 = v11;

    pExceptionObject[0] = &v23;

    pExceptionObject[1] = 0;

    v13 = (*(__int64 (__fastcall **)(__int64, __int64, __int64))(*(_QWORD *)v11 + 8LL))(v11, 96, 16);

    *(_QWORD *)(v13 + 16) = v12;

    *(_DWORD *)(v13 + 8) = 1;

    *(_DWORD *)(v13 + 12) = 1;

    *(_QWORD *)v13 = &std::_Ref_count_obj_alloc3<Hyperion::CallbackListEntry,RSL::Detail::Allocator<Hyperion::CallbackListEntry>>::`vftable';

    v14 = v13 + 32;

    *(_OWORD *)(v13 + 32) = 0;

    *(_QWORD *)(v13 + 40) = 0;

    *(_QWORD *)(v13 + 48) = 0;

    if ( v13 != -56 )

      sub_74F0(v13 + 56, "HookListWake", 0);

    if ( v13 != -64 )

      sub_8BA0(v13 + 64, "HookListGuard", 0);

    *(_QWORD *)(v13 + 72) = sub_4E31E80;

    *(_QWORD *)(v13 + 80) = v9;

    *(_WORD *)(v13 + 88) = 0;

    *(_BYTE *)(v13 + 90) = 0;

  }

  else

  {

    v15 = sub_495A700(80);

    v13 = v15;

    if ( v15 == 0 )

    {

      sub_6F4C20(pExceptionObject);

      throw (std::bad_alloc *)pExceptionObject;

    }

    *(_DWORD *)(v15 + 8) = 1;

    *(_DWORD *)(v15 + 12) = 1;

    *(_QWORD *)v15 = &std::_Ref_count_obj2<Hyperion::CallbackListEntry>::`vftable';

    v14 = v15 + 16;

    *(_OWORD *)(v15 + 16) = 0;

    *(_QWORD *)(v15 + 24) = 0;

    *(_QWORD *)(v15 + 32) = 0;

    if ( v15 != -40 )

      sub_74F0(v15 + 40, "HookListWake", 0);

    if ( v13 != -48 )

      sub_8BA0(v13 + 48, "HookListGuard", 0);

    *(_QWORD *)(v13 + 56) = sub_4E31E80;

    *(_QWORD *)(v13 + 64) = v9;

    *(_WORD *)(v13 + 72) = 0;

    *(_BYTE *)(v13 + 74) = 0;

  }

  *a2 = v14;

  v16 = a2[1];

  a2[1] = v13;

  if ( v16 != 0 )

    sub_705270(v16);

  v17 = (PSLIST_ENTRY)*a2;

  v18 = a2[1];

  if ( v18 != 0 )

    _InterlockedIncrement((volatile signed __int32 *)(v18 + 8));

  v19 = a2[1];

  *((_QWORD *)&v17->Next + 1) = *a2;

  Next = v17[1].Next;

  v17[1].Next = (struct _SLIST_ENTRY *)v19;

  if ( Next != nullptr )

    sub_705270(Next);

  InterlockedPushEntrySList(&ListHead, (PSLIST_ENTRY)*a2);

  result = a2;

  return result;

}

```
The two branches at `0x4E31770` and `0x4E31791` are the two constructor paths selected by `byte_829C78C`. Both produce a `CallbackListEntry`; the alloc3 variant reserves 96 bytes and the obj2 variant 80. Both install `sub_4E31E80` at `+0x48`/`+0x38` as the callback and `v9` at `+0x50`/`+0x40` as its argument, and both create the two named sync objects.

The error I made: `HookListWake` and `HookListGuard` sit adjacent to `TrackedImagesGuard` in `.rdata`, so I assumed they were the same family of guard and therefore belonged to the same container. They are not. They are per-entry named sync objects on the callback. The decompiler's type information for the vtable resolves it immediately, and that is what I should have checked first.

### The trampoline

```c

__int64 __fastcall sub_4E31E80(__int64 a1)

{

  unsigned __int8 v2;

  __int64 v3;

  __int64 result;

  v2 = (*(__int64 (__fastcall **)(_QWORD))(a1 + 40))(*(unsigned int *)(a1 + 32));

  sub_722620(a1);

  sub_495A1C0(a1, v3);

  result = v2;

  return result;

}

```
Reads the event id from `+0x20`, the real callback pointer from `+0x28`, calls it, then releases and frees the entry. This is what runs when a registered callback fires.

### Where these entries go

`InterlockedPushEntrySList(&ListHead, ...)` - a Windows SList. Four functions push: `sub_4E31640`,

`sub_4E318C0`, `sub_4E31B50`, and `pfnwk` at `0x4E2AE7F`. Two consume: `sub_67FE90` and `pfnwk`

itself. That is the subscription mechanism, and `sub_4E310C0`'s broadcast is what walks it.

## Following the event reporting path

`sub_4E2E740` is a 0x2130-byte dispatcher shared by all 14 event types. It is heavily obfuscated roughly a dozen literal byte tables are written to stack frames at the start, and a jump table at `0x4E30830` selects the branch for the event id. It builds fifteen or so `std::string`

arguments, then hands the payload to `sub_4E31510`.

`sub_4E31510` calls `sub_70BBB0()`, which returns the telemetry singleton at `unk_8AA0CA0`

(0xE0 bytes, magic-static guarded by `dword_8AA0DD8`), and then `sub_295CB50(shared_ptr, shared_ptr, string, true)`. That function begins with `test byte ptr [rax+0x68], 2`, a feature bit on the sink object.

The send itself is the last thing the dispatcher does, at `0x4E306C5`:

```asm

movsxd rcx, dword ptr [rax+4]

add    rcx, rdx

mov    rax, [rcx]

mov    rax, [rax+30h]

call   cs:__guard_dispatch_icall_fptr

```
A CFG-indirect virtual call on vtable slot `+0x30`. This is the part that leaves the client, and it is worth being precise about it: it is ****not**** behind the `ctx[0x10]` gate and ****not**** behind the DFLog level check. Those two only gate the blocklist lookup and the log line respectively.

The dispatcher is generic machinery shared with the other thirteen events.

## I also ended up looking at ClientMemStatus

While mapping the FLog channel registrations I found `sub_4E1A9D0`, which is a genuine packed-protocol decoder and the only part of this block that is fully alive. Its channel is registered by `sub_4E236A0`, same shape as `ClientBlockedImage` but 1 argument:

```c

void RegisterClientMemStatusChannel(void)

{

  sub_4991AD0(qword_8A927F8, "ClientMemStatus", &qword_7E51F68, 1);

}

```
### What it does

`sub_4E1A9D0` is a ****framing and validation layer****. It does not decode the payload itself. It parses an 8-byte header, runs six bounds checks, and if the record type is correct, hands the parsed slices to `sub_4E1AE00`, which is the real decoder and where the five format strings live.

### The wire format

```

[ 0:2]  tag       u16  big-endian    -> v14, must be 0xD84F

[ 2:4]  subtype   u16  big-endian    -> v15

[ 4:8]  length    u32                -> v19

```
The length field is the part that looks wrong until you work through it:

```c

v16 = *(unsigned __int8 *)(v6 + 7);

v17 = (*(unsigned __int8 *)(v6 + 6)

v19 = v16 | (unsigned int)v17;

```
Expanding that: byte 4 and byte 5 form a big-endian `u16` that becomes the ****high**** half, byte 6 and byte 7 form a big-endian `u16` that becomes the ****low**** half. So:

```

v19 = b5 | (b4 << 8) | (b6 << 16) | (b7 << 24)

```
The two 16-bit fields are big-endian; only their concatenation order is unusual. In my first pass I described this as a compiler hoisting artifact and a "16-bit word swap", which was incorrect - it is deliberate encoding, and `_byteswap_ushort` on the two leading fields confirms the intent.

### The guards

```c

v4  = a4[1];                       // payload size

v6  = *a4;                         // payload ptr

if ( v4 < 8 )                                       -> QeCounter 0x3F9AE005

v13 = v4 - 8;

v14 = _byteswap_ushort( *(_WORD *)v6 );

v15 = _byteswap_ushort( *(_WORD *)(v6 + 2) );

v19 = <the length field above>;

if ( v19 > v13 )                                     -> QeCounter 0xFBBA12AC

v22 = v19;

v23 = v6 + 8 + v19;                                  // end of header record

v24 = v13 - v19;                                     // remaining after header

if ( v24 < 4 )                                       -> QeCounter 0x896AAFD9

v25 = v24 - 4;

v26 = v23[3];

v27 = (v23[2] | ((v23[1] | (*v23 << 8)) << 8)) << 8;

v28 = v23 + 4;                                       // start of body

v29 = v26 | v27;                                     // body length

if ( v29 > v25 )                                     -> QeCounter 0x986EB00D

v30 = v25 - v29;

if ( v30 != 0 )                                      -> QeCounter 0x1504AC1E

```
Six rejections, each with its own telemetry code, and one success path:

```c

if ( v14 == 0xD84F )

{

  // header slice : { v18, v22 }

  // body slice   : { v28, v29 }

  return sub_4E1AE00(a1, a2, v15, &header, &body);

}

sub_4E3AAA0(1697981976, 0, ...);                     -> QeCounter 0x65352618

```
The tag gate is the notable part. Only tag `0xD84F` gets decoded. Anything else is counted and dropped - which means `sub_4E1AE00` never has to handle malformed input, and the five format strings are only reachable for one specific record type.

### The format strings

`0x7181230`: `[FLog::ClientMemStatus] {}`.

`0x7181288`: `[FLog::ClientMemStatus] {}.{}`.

`0x7181250`: `[FLog::ClientMemStatus] {}.{}.{}`.

`0x7181398`: `[FLog::ClientMemStatus] {}.{}.{}.{}`.

`0x7181538`: `[FLog::ClientMemStatus] {}.{}.0`.

## The counter values I noted down

Both counters funnel into `sub_2E00B00` -> `sub_2DF2BF0`, the shared counter map.

`sub_4E3AAA0` is `QeCounter`, keyed `"code"` with a `"status"` key gated on `byte_874F5E8`:

```c

__int64 __fastcall sub_4E3AAA0(__int64 a1, __int64 a2, __int64 a3, __int64 a4)

{

  const char *v7;

  __int64 v8;

  _BYTE v9[40];

  _BYTE v10[680];

  _BYTE v11[8];

  _BYTE v12[56];

  sub_70E630(v9, &off_7E521F8, a3, a4);

  v7 = "code";

  v8 = 4;

  sub_2E00B00(v11, &v7, a1, 1, v7, v8);

  if ( byte_874F5E8 != 0 )

  {

    v7 = "status";

    v8 = 6;

    sub_2E00B00(v11, &v7, a2, 1);

  }

  sub_2DF2BF0(v12);

  sub_70E7C0(v9);

  sub_70E440(v11);

  return sub_722920(v10);

}

```
`0x3F9AE005` (`sub_4E3AAA0`): payload < 8 bytes.

`0xFBBA12AC` (`sub_4E3AAA0`): header length > remaining.

`0x896AAFD9` (`sub_4E3AAA0`): remaining < 4.

`0x986EB00D` (`sub_4E3AAA0`): body length > remaining.

`0x1504AC1E` (`sub_4E3AAA0`): trailing bytes not clean.

`0x65352618` (`sub_4E3AAA0`): record tag not `0xD84F`.

`0xF19D56FC` (`sub_4E3ABA0`): `ClientBlockedImage`: blocklist hit (unreachable).

`0x986EB00D` spells `B00D` in the low half - someone on that team has a sense of humour.

## Where I ended up

****Live in this build****

The loader notification broadcast and the handler fan-out (`sub_4E2B330` -> `sub_4E310C0`) The ctx singleton and its `+0x10` feature gate The name normalisation and the `unordered_set::find` in `sub_4E2E340`

The `Hyperion::CallbackListEntry` registration machinery and the SList The `ClientMemStatus` framing decoder and all six of its guards All seven telemetry codes

****Dead in this build****

`unk_8BE6110` has no writer I could identify in the static code. Whether it gets populated later still needs runtime confirmation.

****Cosmetic****

The `[DFLog::ClientBlockedImage] Blocked DLL: {}` line, gated on `qword_7E51F78` bytes 0 and 1 being at least 6 and 2. Not visible at release verbosity.

****Not present statically****

Any blocklist entries that might be supplied at runtime by protected code.

Hyperion's integrity verification of `.text`.

## What I can actually conclude

The useful output of this reversal is not "here is a hole". It is a map of the reporting surface.

The `QeCounter` codes are fingerprints: they let you tell, from telemetry, which detector fired and under which guard, and correlate that against what goes out over the wire. The `ClientBlockedImage` lookup is interesting because the static path alone does not explain where the blocklist would come from.

What this reversal deliberately does not do is tell you how to defeat anything. The code described here lives in unencrypted `.text`, which means it is covered by integrity checking that this static view cannot see. Any conclusion of the form "patch this byte" derived from the above is unfalsifiable from here, and stating one would be worse than saying nothing.

The direction this analysis actually supports is the defensive one, and the network side: the `PingItem` detection word that surfaces the same enforcement state on the wire, and the packed record protocols like `ClientMemStatus` that carry it.

## Decompiled

If you want to look into this yourself, check out `sub_4E2E340`, `sub_4E2AB90`, `sub_4E2B330`, `sub_4E310C0`, `sub_4E31640`, `sub_4E31E80`, `sub_4E3ABA0`, `sub_4E3AAA0`, and `sub_4E2E120`.

These are the main functions I looked at while reversing this. Feel free to dig into them yourself and see what you find.
