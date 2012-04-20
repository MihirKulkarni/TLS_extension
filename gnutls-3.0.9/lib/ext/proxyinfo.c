/*
 * Copyright (C) 2001, 2004, 2005, 2010 Free Software Foundation, Inc.
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

/* This file contains the code for the Max Record Size TLS extension.
 */

#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include <gnutls_extensions.h>
#include <ext/proxyinfo.h>
#include "get_ip.c"
static int _proxyinfo_recv_params (gnutls_session_t session, const opaque * data,
                          size_t data_size);
static int _proxyinfo_send_params (gnutls_session_t session, gnutls_buffer_st* data);
static int _proxyinfo_pack (extension_priv_data_t epriv, gnutls_buffer_st * ps);
static int _proxyinfo_unpack (gnutls_buffer_st * ps, extension_priv_data_t * epriv);

extension_entry_st proxyinfo_ext = {
         .name = "PROXYINFO",
         .type = GNUTLS_EXTENSION_PROXYINFO,
         .parse_type = GNUTLS_EXT_APPLICATION,
         .recv_func = _proxyinfo_recv_params,
         .send_func = _proxyinfo_send_params,
         .pack_func = _proxyinfo_pack,
         .unpack_func = _proxyinfo_unpack,
         .deinit_func = NULL
       };

static int _proxyinfo_recv_params (gnutls_session_t session, const opaque * data,
                          size_t _data_size)
{
//printf("Recv params\n");
  int i;
  const unsigned char *p;
  uint16_t len, type;
  ssize_t data_size = _data_size;
  int server_names = 0;
  ProxyInfo_ext_st *priv;
  extension_priv_data_t epriv;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      DECR_LENGTH_RET (data_size, 2, 0);
      len = _gnutls_read_uint16 (data);

      if (len != data_size)
        {
          /* This is unexpected packet length, but
           * just ignore it, for now.
           */
          gnutls_assert ();
          return 0;
        }

      p = data + 2;

      
      DECR_LEN (data_size, 2);
      unsigned count = _gnutls_read_uint16 (p);
      p+=2;
      printf("Received Proxy_Info for %d intermediate proxies\n",count+1);
      priv = gnutls_calloc (1, sizeof (*priv));
      if (priv == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
      priv->proxy_cnt=count;
      
      for (int proxy_id=0;proxy_id<count+1;proxy_id++){
      DECR_LEN (data_size, 2);
      unsigned cipher_algo = _gnutls_read_uint16 (p);
      p+=2;
      DECR_LEN (data_size, 2);
      unsigned kx_algo = _gnutls_read_uint16 (p);
      p+=2;
      DECR_LEN (data_size, 2);
      unsigned mac_algo = _gnutls_read_uint16 (p);
      p+=2;
      DECR_LEN (data_size, 2);
      unsigned ip_addr = _gnutls_read_uint16 (p);
      p+=2;
      DECR_LEN (data_size, 2);
      unsigned mac_addr = _gnutls_read_uint16 (p);
      p+=2;
      //printf("%d %d %d %d %d\n",cipher_algo,kx_algo,mac_algo,ip_addr,mac_addr);

      priv->proxy_info[proxy_id].cipher_algo=cipher_algo;
      priv->proxy_info[proxy_id].kx_algo=kx_algo;
      priv->proxy_info[proxy_id].mac_algo=mac_algo;
      priv->proxy_info[proxy_id].ip_addr=ip_addr;
      priv->proxy_info[proxy_id].mac_addr=mac_addr;
}
      printf("Stored the proxy_info to local instance of extension...\n");
      /* Count all server_names in the packet. */
      while (data_size > 0)
        {
          DECR_LENGTH_RET (data_size, 1, 0);
          p++;

          DECR_LEN (data_size, 2);
          len = _gnutls_read_uint16 (p);
          p += 2;

          if (len > 0)
            {
              DECR_LENGTH_RET (data_size, len, 0);
              server_names++;
              p += len;
            }
          else
            _gnutls_handshake_log
              ("HSK[%p]: Received (0) size server name (under attack?)\n",
               session);

        }

      /* we cannot accept more server names.
       */
      if (server_names > MAX_SERVER_NAME_EXTENSIONS)
        {
          _gnutls_handshake_log
            ("HSK[%p]: Too many server names received (under attack?)\n",
             session);
          server_names = MAX_SERVER_NAME_EXTENSIONS;
        }

      if (server_names == 0)
        return 0;               /* no names found */


      priv->server_names_size = server_names;

      p = data + 4;
      p+=10*(count+1);
      for (i = 0; i < server_names; i++)
        {
          type = *p;
          p++;

          len = _gnutls_read_uint16 (p);
          p += 2;

          switch (type)
            {
            case 0:            /* NAME_DNS */
              if (len <= MAX_SERVER_NAME_SIZE)
                {
                  memcpy (priv->server_names[i].name, p, len);
                  priv->server_names[i].name_length = len;
                  priv->server_names[i].type = GNUTLS_NAME_DNS;
                  break;
                }
            }

          /* move to next record */
          p += len;
        }

      epriv.ptr = priv;
      _gnutls_ext_set_session_data (session, GNUTLS_EXTENSION_PROXYINFO,
                                    epriv);

    }

  return 0;
     }
     
     static int _proxyinfo_send_params (gnutls_session_t session, gnutls_buffer_st* extdata)
     {
//printf("Send params\n");
  uint16_t len;
  unsigned i;
  int total_size = 0, ret;
  ProxyInfo_ext_st *priv;
  extension_priv_data_t epriv;

  ret =
    _gnutls_ext_get_session_data (session, GNUTLS_EXTENSION_PROXYINFO,
                                  &epriv);
  if (ret < 0)
    return 0;


  /* this function sends the client extension data (dnsname)
   */
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      priv = epriv.ptr;

      if (priv->server_names_size == 0)
        return 0;

      /* uint16_t
       */
      total_size = 2;
      total_size+=2; //2 byte for 16 bit integer proxy_count
      total_size+=(sizeof(gnutls_ProxyInfo_ext)/2)*((priv->proxy_cnt)+1);
      for (i = 0; i < priv->server_names_size; i++)
        {
          /* count the total size
           */
          len = priv->server_names[i].name_length;

          /* uint8_t + uint16_t + size
           */
          total_size += 1 + 2 + len;
        }

      /* UINT16: write total size of all names
       */

      ret = _gnutls_buffer_append_prefix(extdata, 16, total_size - 2);
      ret = _gnutls_buffer_append_prefix(extdata, 16, priv->proxy_cnt);
      int count=priv->proxy_cnt;
      for(int proxy_id=0;proxy_id<count+1;proxy_id++){
      ret = _gnutls_buffer_append_prefix(extdata, 16, priv->proxy_info[proxy_id].cipher_algo);
      ret = _gnutls_buffer_append_prefix(extdata, 16, priv->proxy_info[proxy_id].kx_algo);
      ret = _gnutls_buffer_append_prefix(extdata, 16, priv->proxy_info[proxy_id].mac_algo);
      ret = _gnutls_buffer_append_prefix(extdata, 16, priv->proxy_info[proxy_id].ip_addr);
      ret = _gnutls_buffer_append_prefix(extdata, 16, priv->proxy_info[proxy_id].mac_addr);
      }
              
      if (ret < 0)
        return gnutls_assert_val(ret);

      for (i = 0; i < priv->server_names_size; i++)
        {

          switch (priv->server_names[i].type)
            {
            case GNUTLS_NAME_DNS:
              len = priv->server_names[i].name_length;
              if (len == 0)
                break;

              /* UINT8: type of this extension
               * UINT16: size of the first name
               * LEN: the actual server name.
               */
              ret = _gnutls_buffer_append_prefix(extdata, 8, 0);
              if (ret < 0)
                return gnutls_assert_val(ret);

              ret = _gnutls_buffer_append_data_prefix(extdata, 16, priv->server_names[i].name, len);
              if (ret < 0)
                return gnutls_assert_val(ret);

              break;
            default:
              gnutls_assert ();
              return GNUTLS_E_INTERNAL_ERROR;
            }
        }
    }

  return total_size;
     }
     

int
gnutls_proxyinfo_get (gnutls_session_t session, void *data,
                        size_t * data_length,
                        unsigned int *type, unsigned int indx)
{
  printf("Get data from the extension...\n");
  char *_data = data;
  ProxyInfo_ext_st *priv;
  int ret;
  extension_priv_data_t epriv;

  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret =
    _gnutls_ext_get_session_data (session, GNUTLS_EXTENSION_PROXYINFO,
                                  &epriv);

  if (ret < 0)
    {

      gnutls_assert ();
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  priv = epriv.ptr;

  if (indx + 1 > priv->server_names_size)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  *type = priv->server_names[indx].type;
//printf("%s",priv->server_names[0].name);
printf("Re-confirming proxy index: %d\n",priv->proxy_cnt);

if(*data_length>(priv->proxy_cnt+1)*sizeof(gnutls_ProxyInfo_ext)+2){
//great we have the memory, go ahead
      *data_length = (priv->proxy_cnt+1)*sizeof(gnutls_ProxyInfo_ext);
for(int proxy_id=0;proxy_id<priv->proxy_cnt+1;proxy_id++){
      memcpy (data+(proxy_id*sizeof(gnutls_ProxyInfo_ext)),&(priv->proxy_info[proxy_id].cipher_algo) , sizeof(int));
      memcpy (data+(proxy_id*sizeof(gnutls_ProxyInfo_ext)+4), &(priv->proxy_info[proxy_id].kx_algo), sizeof(int));
      memcpy (data+(proxy_id*sizeof(gnutls_ProxyInfo_ext)+8), &(priv->proxy_info[proxy_id].mac_algo), sizeof(int));
      memcpy (data+(proxy_id*sizeof(gnutls_ProxyInfo_ext)+12), &(priv->proxy_info[proxy_id].ip_addr), sizeof(int));
      memcpy (data+(proxy_id*sizeof(gnutls_ProxyInfo_ext)+16), &(priv->proxy_info[proxy_id].mac_addr), sizeof(int));
/*
printf("%d ",priv->proxy_info[proxy_id].cipher_algo);
printf("%d ",priv->proxy_info[proxy_id].kx_algo);
printf("%d ",priv->proxy_info[proxy_id].mac_algo);
printf("%d ",priv->proxy_info[proxy_id].ip_addr);
printf("%d\n",priv->proxy_info[proxy_id].mac_addr);*/
}
printf("Packed extension data into a datagram and returned...\n");
      

}
else{
      *data_length = (priv->proxy_cnt+1)*sizeof(gnutls_ProxyInfo_ext);
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }


  /*if (*data_length >            // greater since we need one extra byte for the null 
      priv->server_names[indx].name_length)
    {
      *data_length = priv->server_names[indx].name_length;
      memcpy (data, priv->server_names[indx].name, *data_length);
      if (*type == GNUTLS_NAME_DNS)     // null terminate 
        _data[(*data_length)] = 0;

    }
  else
    {
      *data_length = priv->server_names[indx].name_length;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }
*/
  return 0;
}
gnutls_ProxyInfo_ext get_proxy_info(gnutls_session_t session)
{
gnutls_ProxyInfo_ext cur_proxy_info;
char p[16];
strcpy(p,get_ip());
cur_proxy_info.cipher_algo = gnutls_cipher_get(session);//rand()%20;
cur_proxy_info.kx_algo = gnutls_kx_get(session);
cur_proxy_info.mac_algo = gnutls_mac_get(session);
cur_proxy_info.ip_addr=get_ip_int(p);//get_cur_ip_addr();
cur_proxy_info.mac_addr=rand()%20;//get_cur_max_addr();
return cur_proxy_info;
}

int
gnutls_proxyinfo_set (gnutls_session_t session,
                        gnutls_server_name_type_t type,
                        const void *name, size_t name_length, void *data,int data_length, int proxy_id)
{
  printf("Set Data locally in the extension...\n");
  int server_names, ret;
  ProxyInfo_ext_st *priv;
  extension_priv_data_t epriv;
  int set = 0;

/*	Fill the contents of foobar_info
 *	in foobar_ext_st structure viz. priv
 *	Temporarily it is filled only for GNUTLS_CLIENT
 */


  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
  
  if(data_length/sizeof(gnutls_ProxyInfo_ext) > MAX_PROXIES - 1 )
    return GNUTLS_E_SHORT_MEMORY_BUFFER;
  if (name_length > MAX_SERVER_NAME_SIZE)
    return GNUTLS_E_SHORT_MEMORY_BUFFER;

  ret =
    _gnutls_ext_get_session_data (session, GNUTLS_EXTENSION_PROXYINFO,
                                  &epriv);
  if (ret < 0)
    {
      set = 1;
    }

  if (set != 0)
    {
      priv = gnutls_calloc (1, sizeof (*priv));
      if (priv == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_MEMORY_ERROR;
        }
      epriv.ptr = priv;
    }
  else
    priv = epriv.ptr;

  server_names = priv->server_names_size + 1;
  if (server_names > MAX_SERVER_NAME_EXTENSIONS)
    server_names = MAX_SERVER_NAME_EXTENSIONS;
  priv->server_names[server_names - 1].type = type;
  memcpy (priv->server_names[server_names - 1].name, name, name_length);
  priv->server_names[server_names - 1].name_length = name_length;
  priv->server_names_size++;


  int proxy_index=(data_length/sizeof(gnutls_ProxyInfo_ext)); 

  priv->proxy_cnt=proxy_index;//proxy_id;
  for(int i=0;i<proxy_index;i++){
  priv->proxy_info[i].cipher_algo=*(int*)(data+(i*sizeof(gnutls_ProxyInfo_ext)));
  priv->proxy_info[i].kx_algo=*(int*)(data+(i*sizeof(gnutls_ProxyInfo_ext))+4);
  priv->proxy_info[i].mac_algo=*(int*)(data+(i*sizeof(gnutls_ProxyInfo_ext))+8);
  priv->proxy_info[i].ip_addr=*(int*)(data+(i*sizeof(gnutls_ProxyInfo_ext))+12);
  priv->proxy_info[i].mac_addr=*(int*)(data+(i*sizeof(gnutls_ProxyInfo_ext))+16);
  }
  if(proxy_index>0)
  printf("Past data parsed from data packet and set in Extension...\n");
priv->proxy_info[proxy_index]=get_proxy_info(session);

proxy_id=proxy_index;
printf("Current Proxy Info:\nProxy Index: %d\n%d, %d, %d, %d, %d\n",priv->proxy_cnt,priv->proxy_info[proxy_id].cipher_algo,priv->proxy_info[proxy_id].kx_algo,priv->proxy_info[proxy_id].mac_algo,priv->proxy_info[proxy_id].ip_addr,priv->proxy_info[proxy_id].mac_addr);


  if (set != 0)
    _gnutls_ext_set_session_data (session, GNUTLS_EXTENSION_PROXYINFO,
                                  epriv);
  ret =
    _gnutls_ext_get_session_data (session, GNUTLS_EXTENSION_PROXYINFO,
                                  &epriv);
  return 0;
}


     static int _proxyinfo_pack (extension_priv_data_t epriv, gnutls_buffer_st * ps)
     {
 //        Append the extension's internal state to buffer 
   ProxyInfo_ext_st *priv = epriv.ptr;
  int i, ret;
  BUFFER_APPEND_NUM (ps, priv->proxy_cnt);
  BUFFER_APPEND_NUM (ps, priv->server_names_size);
  for (i = 0; i < priv->server_names_size; i++)
    {
      BUFFER_APPEND_NUM (ps, priv->server_names[i].type);
      BUFFER_APPEND_PFX (ps, priv->server_names[i].name,
                         priv->server_names[i].name_length);
    }

  return 0;

     }
   
     static int _proxyinfo_unpack (gnutls_buffer_st * ps, extension_priv_data_t * _priv)
     {
//         Read the internal state from buffer 
  ProxyInfo_ext_st *priv;
  int i, ret;
  extension_priv_data_t epriv;

  priv = gnutls_calloc (1, sizeof (*priv));
  if (priv == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
//  BUFFER_POP_NUM (ps, priv->proxy_cnt);
/*  BUFFER_POP_NUM (ps, priv->server_names_size);
  for (i = 0; i < priv->server_names_size; i++)
    {
      BUFFER_POP_NUM (ps, priv->server_names[i].type);
      BUFFER_POP_NUM (ps, priv->server_names[i].name_length);
      if (priv->server_names[i].name_length >
          sizeof (priv->server_names[i].name))
        {
          gnutls_assert ();
          return GNUTLS_E_PARSING_ERROR;
        }
      BUFFER_POP (ps, priv->server_names[i].name,
                  priv->server_names[i].name_length);
    }
*/
  epriv.ptr = priv;
  *_priv = epriv;

  return 0;

error:
  gnutls_free (priv);
  return ret;
     }

