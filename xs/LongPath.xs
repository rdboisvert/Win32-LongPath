/*********
; Windows Interface
;
; 1.0	R. Boisvert	8/6/2013
; First release.
*********/

#define PERL_NO_GET_CONTEXT

#define WIN32_LEAN_AND_MEAN

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include "ppport.h"

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <windows.h>
#include <winioctl.h>

#ifndef REPARSE_DATA_BUFFER_HEADER_SIZE
typedef struct _REPARSE_DATA_BUFFER {
  ULONG  ReparseTag;
  USHORT ReparseDataLength;
  USHORT Reserved;
  union {
    struct {
      USHORT SubstituteNameOffset;
      USHORT SubstituteNameLength;
      USHORT PrintNameOffset;
      USHORT PrintNameLength;
      ULONG  Flags;
      WCHAR  PathBuffer[1];
    } SymbolicLinkReparseBuffer;
    struct {
      USHORT SubstituteNameOffset;
      USHORT SubstituteNameLength;
      USHORT PrintNameOffset;
      USHORT PrintNameLength;
      WCHAR  PathBuffer[1];
    } MountPointReparseBuffer;
    struct {
      UCHAR DataBuffer[1];
    } GenericReparseBuffer;
  };
} REPARSE_DATA_BUFFER, *PREPARSE_DATA_BUFFER;
#endif

/**********
; local constants
**********/

STATIC char perr_nohash [] = "unable to create hash!";

/**********
; local functions
**********/

STATIC bool MakeSymbolicLink (WCHAR *target, WCHAR *link, DWORD attrib)

{
#if (_WIN32_WINNT >= 0x0600)
return CreateSymbolicLinkW (link, target,
  attrib & FILE_ATTRIBUTE_DIRECTORY ? SYMBOLIC_LINK_FLAG_DIRECTORY : 0);
#else
target = link = NULL; attrib = 0; /* avoids a warning about not used */
SetLastError (ERROR_INVALID_FUNCTION);
return (0);
#endif
}

STATIC char *_get_DOS_time (LPFILETIME lpFTime, char *pTime)

{
SYSTEMTIME lpSTime [1];

if (!FileTimeToSystemTime (lpFTime, lpSTime))
  { strcpy (pTime, "0,0,0,0,0,0"); }
else
  {
  sprintf (pTime, "%d,%d,%d,%d,%d,%d", lpSTime->wSecond, lpSTime->wMinute,
    lpSTime->wHour, lpSTime->wDay, lpSTime->wMonth - 1, lpSTime->wYear - 1900);
  }
return pTime;
}

/**********
; external functions
**********/

MODULE = Win32::LongPath	PACKAGE = Win32::LongPath

PROTOTYPES: ENABLE

bool
copy_file (WCHAR *from, WCHAR *to)
CODE:
  RETVAL = CopyFileW (from, to, 0);
OUTPUT:
  RETVAL

bool
create_directory (WCHAR *path)
CODE:
  RETVAL = CreateDirectoryW (path, NULL);
OUTPUT:
  RETVAL

void
create_file (WCHAR *path, long access, long dispos, int flags)
CODE:
  int fd;
  HANDLE fh = CreateFileW (path, access, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, dispos, FILE_ATTRIBUTE_NORMAL, NULL);
  if (fh == INVALID_HANDLE_VALUE)
    { XSRETURN_EMPTY; }
  fd = win32_open_osfhandle ((intptr_t)fh, flags);
  if (fd < 0)
    {
    CloseHandle (fh);
    XSRETURN_EMPTY;
    }
  else
    { XSRETURN_IV ((IV)fd); }

bool
find_close (SV* self)
CODE:
  HV* hv = (HV*)SvRV (self);
  HANDLE handle = (HANDLE)SvUVx (*hv_fetchs (hv, "handle", 1));
  RETVAL = FindClose (handle);
OUTPUT:
  RETVAL

void
find_first_file (SV* self, WCHAR *path)
CODE:
  WIN32_FIND_DATAW pinfo [1];

  HANDLE handle = FindFirstFileW (path, pinfo);
  HV* hv = (HV*)SvRV (self);
  if (!hv_stores (hv, "handle", newSVuv ((UV)handle)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "first", newSVpvn ((char *)pinfo->cFileName,
    wcslen (pinfo->cFileName) * sizeof(WCHAR))))
    { Perl_croak (aTHX_ perr_nohash); }

SV*
find_link (WCHAR *path)
CODE:
  DWORD bufsize;
  HANDLE fh;

  /**********
  ; o linked file?
  ; o open file
  ; o reparse data until buffer filled
  **********/

  DWORD attrib = GetFileAttributesW (path);
  if (attrib == INVALID_FILE_ATTRIBUTES)
    { XSRETURN_EMPTY; }
  if (!(attrib & FILE_ATTRIBUTE_REPARSE_POINT))
    { XSRETURN_EMPTY; }
  fh = CreateFileW (path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (fh == INVALID_HANDLE_VALUE)
    { XSRETURN_EMPTY; }
  RETVAL = NULL;
  for (bufsize = sizeof (REPARSE_DATA_BUFFER) + 300; bufsize; bufsize += 300)
    {
    char *pnewbuf, *pbuf;
    DWORD retsize;
    int len = 0;
    REPARSE_DATA_BUFFER *pparse;

    /**********
    ; o create buffer
    ; o get data
    ; o error?
    **********/

    Newx (pbuf, bufsize, char);
    pparse = (REPARSE_DATA_BUFFER *)pbuf;
    if (!DeviceIoControl (fh, FSCTL_GET_REPARSE_POINT, NULL, 0, pparse,
      bufsize, &retsize, NULL))
      {
      Safefree (pbuf);
      if (GetLastError () != ERROR_MORE_DATA)
        { break; }
      continue;
      }

    /**********
    ; extract link value
    **********/

    switch (pparse->ReparseTag)
      {
      case IO_REPARSE_TAG_SYMLINK:
        pnewbuf = (char *)&pparse->SymbolicLinkReparseBuffer.PathBuffer
          [pparse->SymbolicLinkReparseBuffer.PrintNameOffset / 2];
        len = pparse->SymbolicLinkReparseBuffer.PrintNameLength;
        break;
      case IO_REPARSE_TAG_MOUNT_POINT:
        pnewbuf = (char *)&pparse->MountPointReparseBuffer.PathBuffer
          [pparse->MountPointReparseBuffer.PrintNameOffset / 2];
        len = pparse->MountPointReparseBuffer.PrintNameLength;
        break;
      default:
        pnewbuf = NULL;
      }
    if (pnewbuf)
      { RETVAL = newSVpvn (pnewbuf, len); }
    Safefree (pbuf);
    if (pnewbuf)
      { break; }
    }
  CloseHandle (fh);
  if (!RETVAL)
    { XSRETURN_EMPTY; }
OUTPUT:
  RETVAL

SV*
find_next_file (SV* self)
CODE:
  WIN32_FIND_DATAW pinfo [1];

  HV* hv = (HV*)SvRV (self);
  HANDLE handle = (HANDLE)SvUVx (*hv_fetchs (hv, "handle", 1));
  if(!FindNextFileW (handle, pinfo))
    { XSRETURN_EMPTY; }
  RETVAL = newSVpvn ((char *)pinfo->cFileName,
    wcslen (pinfo->cFileName) * sizeof(WCHAR));
OUTPUT:
  RETVAL

DWORD
get_attribs (WCHAR *path)
CODE:
  RETVAL = GetFileAttributesW (path);
  if (RETVAL == INVALID_FILE_ATTRIBUTES)
    { XSRETURN_EMPTY; }
OUTPUT:
  RETVAL

SV*
get_current_directory ()
CODE:
  DWORD len;
  char *bufptr;

  len = GetCurrentDirectoryW (0, 0);
  if (!len)
    { RETVAL = newSVpvn ("", 0); }
  else
    {
    WCHAR *newptr;
    Newx (bufptr, len * sizeof (WCHAR), char);
    GetCurrentDirectoryW (len, (LPWSTR)bufptr);
    newptr = (WCHAR *)bufptr;
    RETVAL = newSVpvn ((char *)newptr, wcslen (newptr) * sizeof (WCHAR));
    Safefree (bufptr);
    }
OUTPUT:
  RETVAL

SV*
get_long_path (WCHAR *path)
CODE:
  DWORD len;
  char *bufptr;

  len = GetLongPathNameW (path, 0, 0);
  if (!len)
    { RETVAL = newSVpvn ("", 0); }
  else
    {
    WCHAR *newptr;
    Newx (bufptr, len * sizeof (WCHAR), char);
    GetLongPathNameW (path, (LPWSTR)bufptr, len);
    newptr = (WCHAR *)bufptr;
    RETVAL = newSVpvn ((char *)newptr, wcslen (newptr) * sizeof (WCHAR));
    Safefree (bufptr);
    }
OUTPUT:
  RETVAL

SV*
get_short_path (WCHAR *path)
CODE:
  DWORD len;
  char *bufptr;

  len = GetShortPathNameW (path, 0, 0);
  if (!len)
    { RETVAL = newSVpvn ("", 0); }
  else
    {
    WCHAR *newptr;
    Newx (bufptr, len * sizeof (WCHAR), char);
    GetShortPathNameW (path, (LPWSTR)bufptr, len);
    newptr = (WCHAR *)bufptr;
    RETVAL = newSVpvn ((char *)newptr, wcslen (newptr) * sizeof (WCHAR));
    Safefree (bufptr);
    }
OUTPUT:
  RETVAL

DWORD
get_last_error ()
CODE:
  RETVAL = GetLastError ();
OUTPUT:
  RETVAL

void
get_stat (WCHAR *path, bool symlink)
CODE:
  HANDLE fh;
  BY_HANDLE_FILE_INFORMATION pfhi [1];
  HV* hv;
  SV* hvref;
  int mode;
  char sTime [40];

  /**********
  ; open FS object and get information
  **********/

  DWORD flags = FILE_FLAG_BACKUP_SEMANTICS;
  if (symlink)
    { flags |= FILE_FLAG_OPEN_REPARSE_POINT; }
  fh = CreateFileW (path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, flags, NULL);
  if (fh == INVALID_HANDLE_VALUE)
    { XSRETURN_EMPTY; }
  if (!GetFileInformationByHandle (fh, pfhi))
    {
    CloseHandle (fh);
    XSRETURN_EMPTY;
    }
  CloseHandle (fh);

  /**********
  ; get attributes and store in hash
  **********/

  hv = newHV ();
  hvref = sv_2mortal (newRV_noinc ((SV *)hv));
  if (!hv_stores (hv, "dev", newSViv (pfhi->dwVolumeSerialNumber)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "ino", newSViv (0)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "attribs", newSViv (pfhi->dwFileAttributes)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (pfhi->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    { mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO; }
  else
    {
    size_t len;

    mode = S_IFREG | S_IRUSR | S_IRGRP | S_IROTH;
    if (!(pfhi->dwFileAttributes & FILE_ATTRIBUTE_READONLY))
      { mode |= S_IWUSR | S_IWGRP | S_IWOTH; }
    len = wcslen (path);
    if (path [len - 4] == '.')
      {
      WCHAR *ext = &path [len - 3];
      if (!_wcsicmp (ext, L"BAT"))
        { mode |= S_IXUSR | S_IXGRP | S_IXOTH; }
      else if (!_wcsicmp (ext, L"CMD"))
        { mode |= S_IXUSR | S_IXGRP | S_IXOTH; }
      else if (!_wcsicmp (ext, L"COM"))
        { mode |= S_IXUSR | S_IXGRP | S_IXOTH; }
      else if (!_wcsicmp (ext, L"EXE"))
        { mode |= S_IXUSR | S_IXGRP | S_IXOTH; }
      }
    }
  if (!hv_stores (hv, "mode", newSViv (mode)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "nlink", newSViv (1)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "uid", newSViv (0)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "gid", newSViv (0)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "rdev", newSViv (pfhi->dwVolumeSerialNumber)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "atime",
    newSVpv (_get_DOS_time (&pfhi->ftLastAccessTime, sTime), 0)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "mtime",
    newSVpv (_get_DOS_time (&pfhi->ftLastWriteTime, sTime), 0)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "ctime",
    newSVpv (_get_DOS_time (&pfhi->ftCreationTime, sTime), 0)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (mode & S_IFDIR)
    {
    if (!hv_stores (hv, "size_high", newSViv (0)))
      { Perl_croak (aTHX_ perr_nohash); }
    if (!hv_stores (hv, "size_low", newSViv (0)))
      { Perl_croak (aTHX_ perr_nohash); }
    }
  else
    {
    if (!hv_stores (hv, "size_high", newSViv (pfhi->nFileSizeHigh)))
      { Perl_croak (aTHX_ perr_nohash); }
    if (!hv_stores (hv, "size_low", newSViv (pfhi->nFileSizeLow)))
      { Perl_croak (aTHX_ perr_nohash); }
    }
  ST (0) = hvref;
  XSRETURN (1);

void
get_vol_info (WCHAR *path)
CODE:
  DWORD serial_number;
  DWORD max_comp_len;
  DWORD sys_flags;
  WCHAR pname [MAX_PATH + 1];
  HV* hv;
  SV* hvref;

  /**********
  ; get info
  **********/

  if (!GetVolumeInformationW (path, pname, MAX_PATH + 1,
    &serial_number, &max_comp_len, &sys_flags, NULL, 0))
    { XSRETURN_EMPTY; }

  /**********
  ; get info and store in hash
  **********/

  hv = newHV ();
  hvref = sv_2mortal (newRV_noinc ((SV *)hv));
  if (!hv_stores (hv, "serial", newSViv (serial_number)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "maxlen", newSViv (max_comp_len)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "sysflags", newSViv (sys_flags)))
    { Perl_croak (aTHX_ perr_nohash); }
  if (!hv_stores (hv, "name", newSVpvn ((char *)pname,
    wcslen (pname) * sizeof(WCHAR))))
    { Perl_croak (aTHX_ perr_nohash); }
  ST (0) = hvref;
  XSRETURN (1);

bool
make_hlink (WCHAR *target, WCHAR *link)
CODE:
  RETVAL = CreateHardLinkW (link, target, NULL);
OUTPUT:
  RETVAL

bool
make_slink (WCHAR *target, WCHAR *link)
CODE:
  DWORD attrib = GetFileAttributesW (target);
  if (attrib == INVALID_FILE_ATTRIBUTES)
    { XSRETURN_EMPTY; }
  RETVAL = MakeSymbolicLink (target, link, attrib);
OUTPUT:
  RETVAL

bool
move_file (WCHAR *from, WCHAR *to)
CODE:
  RETVAL = MoveFileW (from, to);
OUTPUT:
  RETVAL

bool
remove_directory (WCHAR *path)
CODE:
  RETVAL = RemoveDirectoryW (path);
OUTPUT:
  RETVAL

bool
remove_file (WCHAR *path)
CODE:
  RETVAL = DeleteFileW (path);
OUTPUT:
  RETVAL

bool
set_current_directory (WCHAR *path)
CODE:
  RETVAL = SetCurrentDirectoryW (path);
OUTPUT:
  RETVAL

#ifndef _USE_32BIT_TIME_T
#define _USE_32BIT_TIME_T
#endif

bool
set_attribs (WCHAR *path, DWORD attribs)
CODE:
  RETVAL = SetFileAttributesW (path, attribs);
OUTPUT:
  RETVAL

bool
set_filetime (time_t atime, time_t mtime, WCHAR *path)
CODE:
  struct _utimbuf putb [1];
  putb->actime = atime;
  putb->modtime = mtime;
  if (_wutime (path, putb) == -1)
    { XSRETURN_EMPTY; }
  RETVAL = 1;
OUTPUT:
  RETVAL

DWORD
set_last_error (long error_code)
CODE:
  SetLastError (error_code);
  RETVAL = error_code;
OUTPUT:
  RETVAL

#if 0 /* ??? historical data */
int
get_type (SV* varb)
CODE:
  IO* io;
  if (SvROK (varb))
    {
    RETVAL = 9; /* reference */
    if (sv_isobject (varb))
      {
      RETVAL = 10; /* object */
      if (!strcmp (HvNAME (SvSTASH (SvRV (varb))), "Win32::LongPath"))
        RETVAL = 13; /* longpath dir handle */
      }
    }
  else
    {
    switch (SvTYPE (varb))
      {
      case SVt_IV:
        RETVAL = 1; /* integer */
        break;
      case SVt_NV:
        RETVAL = 2; /* double */
        break;
      case SVt_PV:
        RETVAL = 3; /* string */
        break;
      case SVt_PVAV:
        RETVAL = 4; /* array */
        break;
      case SVt_PVHV:
        RETVAL = 5; /* hash */
        break;
      case SVt_PVCV:
        RETVAL = 6; /* code */
        break;
      case SVt_PVIO:
        RETVAL = 10; /* file handle */
        break;
      case SVt_PVGV:
        RETVAL = 7; /* Glob */
        io = GvIOn ((GV*)varb);
        if (io)
          {
          if (IoIFP (io) || IoOFP (io))
            RETVAL = 11; /* file handle */
          if (IoDIRP (io))
            RETVAL = 12; /* native dir handle */
          }
        break;
      case SVt_PVMG:
        RETVAL = 8; /* Magic */
        break;
      default:
        if (SvOK (varb))
          RETVAL = 100; /* unknown */
        else
          RETVAL = 0; /* undef */
      }
    }
OUTPUT:
  RETVAL

#endif
