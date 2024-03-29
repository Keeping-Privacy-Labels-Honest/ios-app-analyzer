# Reused from projprakt and slightly adjusted.
# resused from scala-droid as well. Frankenstein's script.
from dotenv import load_dotenv
import os
import sys
from datetime import datetime
import mitmproxy
from mitmproxy import http, ctx
from mitmproxy.coretypes import multidict
from mitmproxy.flow import Error
import psycopg2
from psycopg2.extras import execute_values

load_dotenv()

conn, cur = None, None
run_id: int  # aka monitoring_id
running_already_called = False


def mdv_to_dict(mdv: multidict) -> dict:
    """
    mitmproxy uses an internal datastructure which allows multiple values for one key.
    This function converts this into a (key, array) dict. It tries to decode the values and keys as well.
    """
    tmp = dict()
    if not mdv:
        return tmp
    for t in mdv.fields:
        # as we only use this for headers and cookies I assume utf-8, else we replace the char
        try:
            key = str(t[0], encoding='utf-8', errors="replace")
        except TypeError:
            key = t[0]
        try:
            tmp[key] = [str(x, encoding='utf-8', errors="replace")
                        for x in t[1:]]
        except TypeError:
            # if only some are not bytestrings than the bytestrings won't be decoded
            # I don't want to handle this here, if this occurs I'll write a clean-up script
            tmp[key] = [str(x) for x in t[1:]]
    return tmp


def request(flow: http.HTTPFlow):
    r: http.HTTPRequest = flow.request
    request_id: int
    try:
        cur.execute("INSERT INTO requests (monitoring_id, start_time, host, port, method, scheme, authority, path, http_version, content) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                    (run_id, datetime.fromtimestamp(r.timestamp_start), r.pretty_host, r.port, r.method, r.scheme, "", r.path, r.http_version, r.content))
        request_id = cur.fetchone()[0]
        conn.commit()
    except psycopg2.Error as e:
        print(e)
        ctx.master.shutdown()

    # try to decode the content and update the row
    try:
        decoded: str = r.content.decode()
        cur.execute("UPDATE requests SET content = %s  WHERE id = %s",
                    (decoded, request_id))
        conn.commit()
    except ValueError:
        pass
    # headers
    decoded_headers: dict = mdv_to_dict(r.headers)
    if len(decoded_headers) > 0:
        # print([(request_id, k, v) for k, v in decoded_headers.items()])
        execute_values(cur, "INSERT INTO headers (request, name, values) VALUES %s",
                       [(request_id, k, v) for k, v in decoded_headers.items()])
        conn.commit()

    # cookies
    decoded_cookies: dict = mdv_to_dict(r.cookies)
    if len(decoded_cookies) > 0:
        # print([(request_id, k, v) for k, v in decoded_headers.items()])
        execute_values(cur, "INSERT INTO cookies (request, name, values) VALUES %s",
                       [(request_id, k, v) for k, v in decoded_cookies.items()])
        conn.commit()


def load(loader: mitmproxy.addonmanager.Loader):
    global conn, cur
    loader.add_option(
        name="monitoring",
        typespec=int,
        default=-1,
        help="The monitoring id"
    )
    conn = psycopg2.connect(host='localhost', port=os.environ['HOST_PORT'], dbname=os.environ['POSTGRES_DB'],
                            user=os.environ['POSTGRES_USER'], password=os.environ['POSTGRES_PASSWORD'])
    cur = conn.cursor()


def running():
    global run_id, running_already_called
    # https://github.com/mitmproxy/mitmproxy/issues/3584 *facepalm*
    if running_already_called:
        return
    else:
        running_already_called = True

    if not ctx.options.monitoring or ctx.options.monitoring == -1:
        print("Monitoring id not specified, shutting down.. (Hint: Use --set monitoring=<id>)", file=sys.stderr)
        ctx.master.shutdown()
    run_id = ctx.options.monitoring
    cur.execute("SELECT 1")
    cur.commit()
    check_one = cur.fetchone()[0]
    if check_one != 1:
        print("Mitm: DB Error!")
        ctx.master.shutdown()
