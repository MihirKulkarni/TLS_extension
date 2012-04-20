/*
 * Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008,
 * 2009, 2010 Free Software Foundation, Inc.
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GnuTLS.
 *
 * The GnuTLS is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 */

/* 
 * This file holds all the buffering code used in gnutls.
 * The buffering code works as:
 *
 * RECORD LAYER: 
 *  1. uses a buffer to hold data (application/handshake),
 *    we got but they were not requested, yet.
 *  (see gnutls_record_buffer_put(), gnutls_record_buffer_get_size() etc.)
 *
 *  2. uses a buffer to hold data that were incomplete (ie the read/write
 *    was interrupted)
 *  (see _gnutls_io_read_buffered(), _gnutls_io_write_buffered() etc.)
 * 
 * HANDSHAKE LAYER:
 *  1. Uses buffer to hold the last received handshake message.
 *  (see _gnutls_handshake_hash_buffer_put() etc.)
 *
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_num.h>
#include <gnutls_record.h>
#include <gnutls_buffers.h>
#include <gnutls_mbuffers.h>
#include <gnutls_state.h>
#include <gnutls_dtls.h>
#include <system.h>
#include <gnutls_constate.h> /* gnutls_epoch_get */
#include <errno.h>
#include <system.h>

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

/* this is the maximum number of messages allowed to queue.
 */
#define MAX_QUEUE 32

/* Buffers received packets of type APPLICATION DATA and
 * HANDSHAKE DATA.
 */
int
_gnutls_record_buffer_put (gnutls_session_t session,
  content_type_t type, uint64* seq, mbuffer_st* bufel)
{

  bufel->type = type;
  memcpy(&bufel->record_sequence, seq, sizeof(*seq));

  _mbuffer_enqueue(&session->internals.record_buffer, bufel);
  _gnutls_buffers_log ("BUF[REC]: Inserted %d bytes of Data(%d)\n",
                       (int) bufel->msg.size, (int) type);

  return 0;
}

/**
 * gnutls_record_check_pending:
 * @session: is a #gnutls_session_t structure.
 *
 * This function checks if there are unread data
 * in the gnutls buffers. If the return value is
 * non-zero the next call to gnutls_record_recv()
 * is guarranteed not to block.
 *
 * Returns: Returns the size of the data or zero.
 **/
size_t
gnutls_record_check_pending (gnutls_session_t session)
{
  return _gnutls_record_buffer_get_size (GNUTLS_APPLICATION_DATA, session);
}

int
_gnutls_record_buffer_get (content_type_t type,
                           gnutls_session_t session, opaque * data,
                           size_t length, opaque seq[8])
{
gnutls_datum_t msg;
mbuffer_st* bufel;

  if (length == 0 || data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  bufel = _mbuffer_head_get_first(&session->internals.record_buffer, &msg);
  if (bufel == NULL)
    return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);

  if (type != bufel->type)
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);

  if (msg.size <= length)
    length = msg.size;

  if (seq)
    memcpy(seq, bufel->record_sequence.i, 8);

  memcpy(data, msg.data, length);
  _mbuffer_head_remove_bytes(&session->internals.record_buffer, length);
  
  return length;
}

inline static void
reset_errno (gnutls_session_t session)
{
  session->internals.errnum = 0;
}

inline static int
get_errno (gnutls_session_t session)
{
int ret;

  if (session->internals.errnum != 0)
    ret = session->internals.errnum;
  else
    ret = session->internals.errno_func (session->
                                          internals.transport_recv_ptr);
  return ret;
}

static ssize_t
_gnutls_dgram_read (gnutls_session_t session, mbuffer_st **bufel,
		    gnutls_pull_func pull_func)
{
  ssize_t i, ret;
  char *ptr;
  size_t max_size = _gnutls_get_max_decrypted_data(session);
  size_t recv_size = MAX_RECV_SIZE(session);
  gnutls_transport_ptr_t fd = session->internals.transport_recv_ptr;

  if (recv_size > max_size)
    recv_size = max_size;

  *bufel = _mbuffer_alloc (0, max_size);
  if (*bufel == NULL)
    return gnutls_assert_val(GNUTLS_E_MEMORY_ERROR);

  ptr = (*bufel)->msg.data;

  session->internals.direction = 0;

  reset_errno (session);
  i = pull_func (fd, ptr, recv_size);

  if (i < 0)
    {
      int err = get_errno (session);

      _gnutls_read_log ("READ: %d returned from %p, errno=%d gerrno=%d\n",
			(int) i, fd, errno, session->internals.errnum);

      if (err == EAGAIN)
        {
          ret = GNUTLS_E_AGAIN;
          goto cleanup;
        }
      else if (err == EINTR)
        {
          ret = GNUTLS_E_INTERRUPTED;
          goto cleanup;
        }
      else
        {
          gnutls_assert ();
          ret = GNUTLS_E_PULL_ERROR;
          goto cleanup;
        }
    }
  else
    {
      _gnutls_read_log ("READ: Got %d bytes from %p\n", (int) i, fd);
      if (i == 0) 
        {
          /* If we get here, we likely have a stream socket.
           * FIXME: this probably breaks DCCP. */
          gnutls_assert ();
          ret = 0;
          goto cleanup;
        }

      _mbuffer_set_udata_size (*bufel, i);
    }

  _gnutls_read_log ("READ: read %d bytes from %p\n", (int) i, fd);
  
  return i;
  
cleanup:
  _mbuffer_xfree(bufel);
  return ret;
}

static ssize_t
_gnutls_stream_read (gnutls_session_t session, mbuffer_st **bufel,
		     size_t size, gnutls_pull_func pull_func)
{
  size_t left;
  ssize_t i = 0;
  size_t max_size = _gnutls_get_max_decrypted_data(session);
  char *ptr;
  gnutls_transport_ptr_t fd = session->internals.transport_recv_ptr;

  *bufel = _mbuffer_alloc (0, MAX(max_size, size));
  if (!*bufel)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  ptr = (*bufel)->msg.data;

  session->internals.direction = 0;

  left = size;
  while (left > 0)
    {
      reset_errno (session);

      i = pull_func (fd, &ptr[size - left], left);

      if (i < 0)
        {
          int err = get_errno (session);

          _gnutls_read_log ("READ: %d returned from %p, errno=%d gerrno=%d\n",
                            (int) i, fd, errno, session->internals.errnum);

          if (err == EAGAIN || err == EINTR)
            {
              if (size - left > 0)
                {

                  _gnutls_read_log ("READ: returning %d bytes from %p\n",
                                    (int) (size - left), fd);

                  goto finish;
                }

              if (err == EAGAIN)
                return GNUTLS_E_AGAIN;
              return GNUTLS_E_INTERRUPTED;
            }
          else
            {
              gnutls_assert ();
              return GNUTLS_E_PULL_ERROR;
            }
        }
      else
        {

          _gnutls_read_log ("READ: Got %d bytes from %p\n", (int) i, fd);

          if (i == 0)
            break;              /* EOF */
        }

      left -= i;
      (*bufel)->msg.size += i;
    }

finish:

  _gnutls_read_log ("READ: read %d bytes from %p\n",
                        (int) (size - left), fd);

  return (size - left);
}


/* This function is like read. But it does not return -1 on error.
 * It does return gnutls_errno instead.
 *
 * Flags are only used if the default recv() function is being used.
 */
static ssize_t
_gnutls_read (gnutls_session_t session, mbuffer_st **bufel,
	      size_t size, gnutls_pull_func pull_func)
{
  if (IS_DTLS (session))
    /* Size is not passed, since a whole datagram will be read. */
    return _gnutls_dgram_read (session, bufel, pull_func);
  else
    return _gnutls_stream_read (session, bufel, size, pull_func);
}

static ssize_t
_gnutls_writev_emu (gnutls_session_t session, gnutls_transport_ptr_t fd, const giovec_t * giovec,
                    int giovec_cnt)
{
  int ret = 0, j = 0;
  size_t total = 0;

  for (j = 0; j < giovec_cnt; j++)
    {
      ret = session->internals.push_func (fd, giovec[j].iov_base, giovec[j].iov_len);

      if (ret == -1)
        break;

      total += ret;

      if (ret != giovec[j].iov_len)
        break;
    }

  if (total > 0)
    return total;

  return ret;
}

static ssize_t
_gnutls_writev (gnutls_session_t session, const giovec_t * giovec,
                int giovec_cnt)
{
  int i;
  gnutls_transport_ptr_t fd = session->internals.transport_send_ptr;

  reset_errno (session);

  if (session->internals.push_func != NULL)
    i = _gnutls_writev_emu (session, fd, giovec, giovec_cnt);
  else
    i = session->internals.vec_push_func (fd, giovec, giovec_cnt);

  if (i == -1)
    {
      int err = get_errno (session);
      _gnutls_debug_log ("errno: %d\n", err);
      if (err == EAGAIN)
        return GNUTLS_E_AGAIN;
      else if (err == EINTR)
        return GNUTLS_E_INTERRUPTED;
      else
        {
          gnutls_assert ();
          return GNUTLS_E_PUSH_ERROR;
        }
    }
  return i;
}

/* This function is like recv(with MSG_PEEK). But it does not return -1 on error.
 * It does return gnutls_errno instead.
 * This function reads data from the socket and keeps them in a buffer, of up to
 * MAX_RECV_SIZE. 
 *
 * This is not a general purpose function. It returns EXACTLY the data requested,
 * which are stored in a local (in the session) buffer.
 *
 */
ssize_t
_gnutls_io_read_buffered (gnutls_session_t session, size_t total,
                          content_type_t recv_type)
{
  ssize_t ret = 0;
  size_t min;
  mbuffer_st *bufel = NULL;
  size_t recvdata, readsize;

  if (total > MAX_RECV_SIZE(session) || total == 0)
    {
      gnutls_assert ();         /* internal error */
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* calculate the actual size, ie. get the minimum of the
   * buffered data and the requested data.
   */
  min = MIN (session->internals.record_recv_buffer.byte_length, total);
  if (min > 0)
    {
      /* if we have enough buffered data
       * then just return them.
       */
      if (min == total)
        {
          return min;
        }
    }

  /* min is over zero. recvdata is the data we must
   * receive in order to return the requested data.
   */
  recvdata = total - min;
  readsize = recvdata;

  /* Check if the previously read data plus the new data to
   * receive are longer than the maximum receive buffer size.
   */
  if ((session->internals.record_recv_buffer.byte_length + recvdata) >
      MAX_RECV_SIZE(session))
    {
      gnutls_assert ();         /* internal error */
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* READ DATA - but leave RCVLOWAT bytes in the kernel buffer.
   */
  if (readsize > 0)
    {
      ret =
        _gnutls_read (session, &bufel, readsize,
                      session->internals.pull_func);

      /* return immediately if we got an interrupt or eagain
       * error.
       */
      if (ret < 0 && gnutls_error_is_fatal (ret) == 0)
        {
          _mbuffer_xfree (&bufel);
          return ret;
        }
    }

  /* copy fresh data to our buffer.
   */
  if (ret > 0)
    {
      _gnutls_read_log
        ("RB: Have %d bytes into buffer. Adding %d bytes.\n",
         (int) session->internals.record_recv_buffer.byte_length, (int) ret);
      _gnutls_read_log ("RB: Requested %d bytes\n", (int) total);

      _mbuffer_enqueue (&session->internals.record_recv_buffer, bufel);
    }
  else
    _mbuffer_xfree (&bufel);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (ret == 0)
    {                           /* EOF */
      gnutls_assert ();
      return 0;
    }

  if(IS_DTLS(session))
    ret = MIN(total, session->internals.record_recv_buffer.byte_length);
  else
    ret = session->internals.record_recv_buffer.byte_length;

  if ((ret > 0) && ((size_t) ret < total))
    {
      /* Short Read */
      return gnutls_assert_val(GNUTLS_E_AGAIN);
    }
  else
    {
      return ret;
    }
}

/* This function is like write. But it does not return -1 on error.
 * It does return gnutls_errno instead.
 *
 * This function takes full responsibility of freeing msg->data.
 *
 * In case of E_AGAIN and E_INTERRUPTED errors, you must call
 * gnutls_write_flush(), until it returns ok (0).
 *
 * We need to push exactly the data in msg->size, since we cannot send
 * less data. In TLS the peer must receive the whole packet in order
 * to decrypt and verify the integrity.
 *
 */
ssize_t
_gnutls_io_write_buffered (gnutls_session_t session,
                           mbuffer_st * bufel, unsigned int mflag)
{
  mbuffer_head_st *const send_buffer = &session->internals.record_send_buffer;

  _mbuffer_enqueue (send_buffer, bufel);

  _gnutls_write_log
    ("WRITE: enqueued %d bytes for %p. Total %d bytes.\n",
     (int) bufel->msg.size, session->internals.transport_recv_ptr,
     (int) send_buffer->byte_length);

  if (mflag == MBUFFER_FLUSH)
    return _gnutls_io_write_flush (session);
  else
    return bufel->msg.size;
}

typedef ssize_t (*send_func) (gnutls_session_t, const giovec_t *, int);

/* This function writes the data that are left in the
 * TLS write buffer (ie. because the previous write was
 * interrupted.
 */
ssize_t
_gnutls_io_write_flush (gnutls_session_t session)
{
  gnutls_datum_t msg;
  mbuffer_head_st *send_buffer = &session->internals.record_send_buffer;
  int ret;
  ssize_t sent = 0, tosend = 0;
  giovec_t iovec[MAX_QUEUE];
  int i = 0;
  mbuffer_st *cur;

  _gnutls_write_log ("WRITE FLUSH: %d bytes in buffer.\n",
                     (int) send_buffer->byte_length);

  for (cur = _mbuffer_head_get_first (send_buffer, &msg);
       cur != NULL; cur = _mbuffer_head_get_next (cur, &msg))
    {
      iovec[i].iov_base = msg.data;
      iovec[i++].iov_len = msg.size;
      tosend += msg.size;

      /* we buffer up to MAX_QUEUE messages */
      if (i >= MAX_QUEUE)
        {
          gnutls_assert ();
          return GNUTLS_E_INTERNAL_ERROR;
        }
    }

  if (tosend == 0)
    {
      gnutls_assert();
      return 0;
    }

  ret = _gnutls_writev (session, iovec, i);
  if (ret >= 0)
    {
      _mbuffer_head_remove_bytes (send_buffer, ret);
      _gnutls_write_log ("WRITE: wrote %d bytes, %d bytes left.\n",
                         ret, (int) send_buffer->byte_length);

      sent += ret;
    }
  else if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN)
    {
      _gnutls_write_log ("WRITE interrupted: %d bytes left.\n",
                         (int) send_buffer->byte_length);
      return ret;
    }
  else
    {
      _gnutls_write_log ("WRITE error: code %d, %d bytes left.\n",
                         ret, (int) send_buffer->byte_length);

      gnutls_assert ();
      return ret;
    }

  if (sent < tosend)
    {
      return gnutls_assert_val(GNUTLS_E_AGAIN);
    }

  return sent;
}

#include "debug.h"
/* Checks whether there are received data within
 * a timeframe.
 *
 * Returns 0 if data were received, GNUTLS_E_TIMEDOUT
 * on timeout and a negative error code on error.
 */
int
_gnutls_io_check_recv (gnutls_session_t session, unsigned int ms)
{
  gnutls_transport_ptr_t fd = session->internals.transport_send_ptr;
  int ret = 0;
  
  if (session->internals.pull_timeout_func == system_recv_timeout && 
    session->internals.pull_func != system_read)
    return gnutls_assert_val(GNUTLS_E_PULL_ERROR);

  ret = session->internals.pull_timeout_func(fd, ms);
  if (ret == -1)
    return gnutls_assert_val(GNUTLS_E_PULL_ERROR);
  
  if (ret > 0)
    return 0;
  else return GNUTLS_E_TIMEDOUT;
}

/* HANDSHAKE buffers part 
 */

/* This function writes the data that are left in the
 * Handshake write buffer (ie. because the previous write was
 * interrupted.
 *
 */
ssize_t
_gnutls_handshake_io_write_flush (gnutls_session_t session)
{
  mbuffer_head_st *const send_buffer =
    &session->internals.handshake_send_buffer;
  gnutls_datum_t msg;
  int ret;
  uint16_t epoch;
  ssize_t total = 0;
  mbuffer_st *cur;

  _gnutls_write_log ("HWRITE FLUSH: %d bytes in buffer.\n",
                     (int) send_buffer->byte_length);

  if (IS_DTLS(session))
    return _dtls_transmit(session);

  for (cur = _mbuffer_head_get_first (send_buffer, &msg);
       cur != NULL; cur = _mbuffer_head_get_first (send_buffer, &msg))
    {
      epoch = cur->epoch;

      ret = _gnutls_send_int (session, cur->type,
                              cur->htype,
                              epoch,
                              msg.data, msg.size, 0);

      if (ret >= 0)
        {
          total += ret;
          
          ret = _mbuffer_head_remove_bytes (send_buffer, ret);
          if (ret == 1)
            _gnutls_epoch_refcount_dec(session, epoch);

          _gnutls_write_log ("HWRITE: wrote %d bytes, %d bytes left.\n",
                             ret, (int) send_buffer->byte_length);

        }
      else
        {
          _gnutls_write_log ("HWRITE error: code %d, %d bytes left.\n",
                             ret, (int) send_buffer->byte_length);

          gnutls_assert ();
          return ret;
        }
    }

  return _gnutls_io_write_flush (session);
}


/* This is a send function for the gnutls handshake 
 * protocol. Just makes sure that all data have been sent.
 *
 */
int
_gnutls_handshake_io_cache_int (gnutls_session_t session,
                                gnutls_handshake_description_t htype,
                                mbuffer_st * bufel)
{
  mbuffer_head_st * send_buffer;

  if (IS_DTLS(session))
    {
      bufel->handshake_sequence = session->internals.dtls.hsk_write_seq-1;
    }
  
  send_buffer =
    &session->internals.handshake_send_buffer;

  bufel->epoch = (uint16_t)_gnutls_epoch_refcount_inc(session, EPOCH_WRITE_CURRENT);

  bufel->htype = htype;
  if (bufel->htype == GNUTLS_HANDSHAKE_CHANGE_CIPHER_SPEC)
    bufel->type = GNUTLS_CHANGE_CIPHER_SPEC;
  else
    bufel->type = GNUTLS_HANDSHAKE;

  _mbuffer_enqueue (send_buffer, bufel);

  _gnutls_write_log
    ("HWRITE: enqueued [%s] %d. Total %d bytes.\n",
     _gnutls_handshake2str (bufel->htype), (int) bufel->msg.size, (int) send_buffer->byte_length);

  return 0;
}

static int handshake_compare(const void* _e1, const void* _e2)
{
const handshake_buffer_st* e1 = _e1;
const handshake_buffer_st* e2 = _e2;

  if (e1->sequence <= e2->sequence)
    return 1;
  else
    return -1;
}

#define SSL2_HEADERS 1
static int
parse_handshake_header (gnutls_session_t session, mbuffer_st* bufel, gnutls_handshake_description_t htype, 
    handshake_buffer_st* hsk)
{
  uint8_t *dataptr = NULL;      /* for realloc */
  size_t handshake_header_size = HANDSHAKE_HEADER_SIZE(session), data_size;

  /* Note: SSL2_HEADERS == 1 */
  if (_mbuffer_get_udata_size(bufel) < handshake_header_size)
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  dataptr = _mbuffer_get_udata_ptr(bufel);

  /* if reading a client hello of SSLv2 */
  if (!IS_DTLS(session) && htype == GNUTLS_HANDSHAKE_CLIENT_HELLO &&
    bufel->htype == GNUTLS_HANDSHAKE_CLIENT_HELLO_V2)
    {
      handshake_header_size = SSL2_HEADERS; /* we've already read one byte */

      hsk->length = _mbuffer_get_udata_size(bufel) - handshake_header_size;    /* we've read the first byte */

      if (dataptr[0] != GNUTLS_HANDSHAKE_CLIENT_HELLO)
        return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);

      hsk->htype = GNUTLS_HANDSHAKE_CLIENT_HELLO_V2;

      hsk->sequence = 0;
      hsk->start_offset = 0;
      hsk->end_offset = hsk->length;
    }
  else /* TLS handshake headers */
    {

      hsk->htype = dataptr[0];

      /* we do not use DECR_LEN because we know
       * that the packet has enough data.
       */
      hsk->length = _gnutls_read_uint24 (&dataptr[1]);
      handshake_header_size = HANDSHAKE_HEADER_SIZE(session);

      if (IS_DTLS(session))
        {
          hsk->sequence = _gnutls_read_uint16 (&dataptr[4]);
          hsk->start_offset = _gnutls_read_uint24 (&dataptr[6]);
          hsk->end_offset = hsk->start_offset + _gnutls_read_uint24 (&dataptr[9]);
        }
      else
        {
          hsk->sequence = 0;
          hsk->start_offset = 0;
          hsk->end_offset = hsk->length;
        }
    }
  data_size = _mbuffer_get_udata_size(bufel) - handshake_header_size;

  /* make the length offset */
  if (hsk->end_offset > 0) hsk->end_offset--;

  _gnutls_handshake_log ("HSK[%p]: %s was received. Length %d[%d], frag offset %d, frag length: %d, sequence: %d\n",
                         session, _gnutls_handshake2str (hsk->htype),
                         (int) hsk->length, (int)data_size, hsk->start_offset, hsk->end_offset-hsk->start_offset+1, (int)hsk->sequence);

  hsk->header_size = handshake_header_size;
  memcpy(hsk->header, _mbuffer_get_udata_ptr(bufel), handshake_header_size);

  if (hsk->length > 0 && 
        (hsk->end_offset-hsk->start_offset >=  data_size))
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);

  if (hsk->length > 0 && (hsk->start_offset >= hsk->end_offset ||
      hsk->end_offset-hsk->start_offset >=  data_size ||
      hsk->end_offset >= hsk->length))
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
  else if (hsk->length == 0 && hsk->end_offset != 0 && hsk->start_offset != 0)
    return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET_LENGTH);
  
  return handshake_header_size;
}

static void _gnutls_handshake_buffer_move(handshake_buffer_st* dst, handshake_buffer_st* src)
{
  memcpy(dst, src, sizeof(*dst));
  memset(src, 0, sizeof(*src));
  src->htype = -1;
}

/* will merge the given handshake_buffer_st to the handshake_recv_buffer
 * list. The given hsk packet will be released in any case (success or failure).
 * Only used in DTLS.
 */
static int merge_handshake_packet(gnutls_session_t session, handshake_buffer_st* hsk)
{
int exists = 0, i, pos = 0;
int ret;

  for (i=0;i<session->internals.handshake_recv_buffer_size;i++)
    {
      if (session->internals.handshake_recv_buffer[i].htype == hsk->htype)
        {
          exists = 1;
          pos = i;
          break;
        }
    }

  if (exists == 0)
    pos = session->internals.handshake_recv_buffer_size;

  if (pos > MAX_HANDSHAKE_MSGS)
    return gnutls_assert_val(GNUTLS_E_TOO_MANY_HANDSHAKE_PACKETS);

  if (exists == 0)
    {
      if (hsk->length > 0 && hsk->end_offset > 0 && hsk->end_offset-hsk->start_offset+1 != hsk->length)
        {
          ret = _gnutls_buffer_resize(&hsk->data, hsk->length);
          if (ret < 0)
            return gnutls_assert_val(ret);
  
          hsk->data.length = hsk->length;
          
          memmove(&hsk->data.data[hsk->start_offset], hsk->data.data, hsk->end_offset-hsk->start_offset+1);
        }
      
      session->internals.handshake_recv_buffer_size++;

      /* rewrite headers to make them look as each packet came as a single fragment */
      _gnutls_write_uint24(hsk->length, &hsk->header[1]);
      _gnutls_write_uint24(0, &hsk->header[6]);
      _gnutls_write_uint24(hsk->length, &hsk->header[9]);

      _gnutls_handshake_buffer_move(&session->internals.handshake_recv_buffer[pos], hsk);

    }
  else
    {
      if (hsk->start_offset < session->internals.handshake_recv_buffer[pos].start_offset &&
        hsk->end_offset >= session->internals.handshake_recv_buffer[pos].start_offset)
        {
          memcpy(&session->internals.handshake_recv_buffer[pos].data.data[hsk->start_offset], 
            hsk->data.data, hsk->data.length);
          session->internals.handshake_recv_buffer[pos].start_offset = hsk->start_offset;
          session->internals.handshake_recv_buffer[pos].end_offset = 
            MIN(hsk->end_offset, session->internals.handshake_recv_buffer[pos].end_offset);
        }
      else if (hsk->end_offset > session->internals.handshake_recv_buffer[pos].end_offset &&
        hsk->start_offset <= session->internals.handshake_recv_buffer[pos].end_offset+1)
        {
          memcpy(&session->internals.handshake_recv_buffer[pos].data.data[hsk->start_offset], 
            hsk->data.data, hsk->data.length);

          session->internals.handshake_recv_buffer[pos].end_offset = hsk->end_offset;
          session->internals.handshake_recv_buffer[pos].start_offset = 
            MIN(hsk->start_offset, session->internals.handshake_recv_buffer[pos].start_offset);
        }
      _gnutls_handshake_buffer_clear(hsk);
    }

  return 0;
}

/* returns non-zero on match and zero on mismatch
 */
inline static int cmp_hsk_types(gnutls_handshake_description_t expected, gnutls_handshake_description_t recvd)
{
  if ((expected != GNUTLS_HANDSHAKE_CLIENT_HELLO || recvd != GNUTLS_HANDSHAKE_CLIENT_HELLO_V2) &&
        (expected != recvd))
    return 0;
  
  return 1; 
}

#define LAST_ELEMENT (session->internals.handshake_recv_buffer_size-1)

/* returns the last stored handshake packet.
 */
static int get_last_packet(gnutls_session_t session, gnutls_handshake_description_t htype,
  handshake_buffer_st * hsk)
{
handshake_buffer_st* recv_buf = session->internals.handshake_recv_buffer;

  if (IS_DTLS(session))
    {
      if (session->internals.handshake_recv_buffer_size == 0 ||
        (session->internals.dtls.hsk_read_seq != recv_buf[LAST_ELEMENT].sequence))
        goto timeout;

      if (htype != recv_buf[LAST_ELEMENT].htype)
        {
          hsk->htype = recv_buf[LAST_ELEMENT].htype;
          return gnutls_assert_val(GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET);
        }

      else if ((recv_buf[LAST_ELEMENT].start_offset == 0 &&
        recv_buf[LAST_ELEMENT].end_offset == recv_buf[LAST_ELEMENT].length -1) || 
        recv_buf[LAST_ELEMENT].length == 0)
        {
          session->internals.dtls.hsk_read_seq++;
          _gnutls_handshake_buffer_move(hsk, &recv_buf[LAST_ELEMENT]);
          session->internals.handshake_recv_buffer_size--;
          return 0;
        }
      else
        goto timeout;
    }
  else /* TLS */
    {
      if (session->internals.handshake_recv_buffer_size > 0 && recv_buf[0].length == recv_buf[0].data.length)
        {
          if (cmp_hsk_types(htype, recv_buf[0].htype) == 0)
            {
              hsk->htype = recv_buf[LAST_ELEMENT].htype;
              return gnutls_assert_val(GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET);
            }

          _gnutls_handshake_buffer_move(hsk, &recv_buf[0]);
          session->internals.handshake_recv_buffer_size--;
          return 0;
        }
      else
        return gnutls_assert_val(GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE);
    }

timeout:
  if (time(0)-session->internals.dtls.handshake_start_time > session->internals.dtls.total_timeout/1000) 
    return gnutls_assert_val(GNUTLS_E_TIMEDOUT);
  else
    {
      if (session->internals.dtls.blocking != 0)
        millisleep(50);
        
      return gnutls_assert_val(GNUTLS_E_AGAIN);
    }
}

/* This is a receive function for the gnutls handshake 
 * protocol. Makes sure that we have received all data.
 */
static int
parse_record_buffered_msgs (gnutls_session_t session,
                               gnutls_handshake_description_t htype,
                               handshake_buffer_st * hsk)
{
  gnutls_datum_t msg;
  mbuffer_st* bufel = NULL, *prev = NULL;
  int ret;
  size_t data_size;
  handshake_buffer_st* recv_buf = session->internals.handshake_recv_buffer;

  bufel = _mbuffer_head_get_first(&session->internals.record_buffer, &msg);
  if (bufel == NULL)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

  if (!IS_DTLS(session))
    {
      ssize_t remain, append, header_size;

      do
        {
          if (bufel->type != GNUTLS_HANDSHAKE)
            return gnutls_assert_val(GNUTLS_E_UNEXPECTED_PACKET);

          /* if we have a half received message the complete it.
           */
          remain =  recv_buf[0].length -
                recv_buf[0].data.length;

          /* this is the rest of a previous message */
          if (session->internals.handshake_recv_buffer_size > 0 && recv_buf[0].length > 0 && remain > 0)
            {
              if (msg.size <= remain)
                append = msg.size;
              else
                append = remain;
                  
              ret = _gnutls_buffer_append_data(&recv_buf[0].data, msg.data, append);
              if (ret < 0)
                return gnutls_assert_val(ret);

              _mbuffer_head_remove_bytes(&session->internals.record_buffer, append);
            }
          else /* received new message */
            {
              ret = parse_handshake_header(session, bufel, htype, &recv_buf[0]);
              if (ret < 0)
                return gnutls_assert_val(ret);

              header_size = ret;
              session->internals.handshake_recv_buffer_size = 1;

              _mbuffer_set_uhead_size(bufel, header_size);

              data_size = MIN(recv_buf[0].length, _mbuffer_get_udata_size(bufel));
              ret = _gnutls_buffer_append_data(&recv_buf[0].data, _mbuffer_get_udata_ptr(bufel), data_size);
              if (ret < 0)
                return gnutls_assert_val(ret);
              _mbuffer_set_uhead_size(bufel, 0);
              _mbuffer_head_remove_bytes(&session->internals.record_buffer, data_size+header_size);

              if (cmp_hsk_types(htype, recv_buf[0].htype) == 0)
                { /* an unexpected packet */
                  hsk->htype = recv_buf[0].htype;
                  return gnutls_assert_val(GNUTLS_E_UNEXPECTED_HANDSHAKE_PACKET);
                }

            }

          /* if packet is complete then return it
           */
          if (recv_buf[0].length ==
                recv_buf[0].data.length)
            {
              return get_last_packet(session, htype, hsk);
            }
          bufel = _mbuffer_head_get_first(&session->internals.record_buffer, &msg);
        } 
      while(bufel != NULL);
    
      /* if we are here it means that the received packets were not
       * enough to complete the handshake packet.
       */
      return gnutls_assert_val(GNUTLS_E_AGAIN);
    }
  else /* DTLS */
    {
      handshake_buffer_st tmp;

      do
        {
          /* we now 
           * 0. parse headers
           * 1. insert to handshake_recv_buffer
           * 2. sort handshake_recv_buffer on sequence numbers
           * 3. return first packet if completed or GNUTLS_E_AGAIN.
           */
          do
            {
              if (bufel->type != GNUTLS_HANDSHAKE)
                {
                  gnutls_assert();
                  goto next; /* ignore packet */
                }

              _gnutls_handshake_buffer_init(&tmp);

              ret = parse_handshake_header(session, bufel, htype, &tmp);
              if (ret < 0)
                {
                  gnutls_assert();
                  _gnutls_audit_log(session, "Invalid handshake packet headers. Discarding.\n");
                  break;
                }

              _mbuffer_consume(&session->internals.record_buffer, bufel, ret);

              data_size = MIN(tmp.length, tmp.end_offset-tmp.start_offset+1);

              ret = _gnutls_buffer_append_data(&tmp.data, _mbuffer_get_udata_ptr(bufel), data_size);
              if (ret < 0)
                return gnutls_assert_val(ret);

              _mbuffer_consume(&session->internals.record_buffer, bufel, data_size);

              ret = merge_handshake_packet(session, &tmp);
              if (ret < 0)
                return gnutls_assert_val(ret);

            }
          while(_mbuffer_get_udata_size(bufel) > 0);

          prev = bufel;
          bufel = _mbuffer_dequeue(&session->internals.record_buffer, bufel);

          _mbuffer_xfree(&prev);
          continue;

next:
          bufel = _mbuffer_head_get_next(bufel, NULL);
        }
      while(bufel != NULL);

      /* sort in descending order */
      if (session->internals.handshake_recv_buffer_size > 1)
        qsort(recv_buf, session->internals.handshake_recv_buffer_size,
          sizeof(recv_buf[0]), handshake_compare);

      while(session->internals.handshake_recv_buffer_size > 0 &&
        recv_buf[LAST_ELEMENT].sequence < session->internals.dtls.hsk_read_seq)
        {
          _gnutls_audit_log(session, "Discarded replayed handshake packet with sequence %d\n", recv_buf[LAST_ELEMENT].sequence);
          _gnutls_handshake_buffer_clear(&recv_buf[LAST_ELEMENT]);
          session->internals.handshake_recv_buffer_size--;
        }

        return get_last_packet(session, htype, hsk);
    }
}

/* This is a receive function for the gnutls handshake 
 * protocol. Makes sure that we have received all data.
 */
ssize_t
_gnutls_handshake_io_recv_int (gnutls_session_t session,
                               gnutls_handshake_description_t htype,
                               handshake_buffer_st * hsk)
{
  int ret;

  ret = get_last_packet(session, htype, hsk);
  if (ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_INTERRUPTED && ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE)
    {
      return gnutls_assert_val(ret);
    }

  /* try using the already existing records before
   * trying to receive.
   */
  ret = parse_record_buffered_msgs(session, htype, hsk);
  if (IS_DTLS(session))
    {
      if (ret >= 0)
        return ret;
    }
  else
    {
      if ((ret != GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE && ret < 0) || ret >= 0)
        return gnutls_assert_val(ret);
    }

  /* if we don't have a complete message waiting for us, try 
   * receiving more */
  ret = _gnutls_recv_in_buffers(session, GNUTLS_HANDSHAKE, htype);
  if (ret < 0)
    return gnutls_assert_val_fatal(ret);

  return parse_record_buffered_msgs(session, htype, hsk); 
}

