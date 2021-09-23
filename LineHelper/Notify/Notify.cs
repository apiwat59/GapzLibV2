using Newtonsoft.Json;
using RestSharp;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace GapzLib.LineHelper.Notify
{
    public static class Notify
    {
        /// <summary>
        /// Token Line Notify Get in Website
        /// </summary>
        public static string LINE_TOKEN { get; set; } = "BCqpwviJjqjIKEZdHGqLEFrjsRyoHKxoBSqtfkLXSaT";

        /// <summary>
        /// send text to line notify 
        /// </summary>
        /// <param name="content"></param>
        public static string Message(string content)
        {
            try
            {
                var QueryString = new Dictionary<string, string>()
                        {
                            {"message",content}
                        };

                return LineReq(Method.POST, "https://notify-api.line.me/api/notify", QueryString).Content;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
        public static string Message(string content, string package_sticker, string stickerid)
        {
            try
            {
                var QueryString = new Dictionary<string, string>()
                        {
                            {"message",content},
                            {"stickerId",stickerid},
                            {"stickerPackageId",package_sticker}
                        };

                return LineReq(Method.POST, "https://notify-api.line.me/api/notify", QueryString).Content;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public static string Message(string content, Tuple<string, string> file)
        {
            try
            {
                if (!File.Exists(file.Item2)) throw new Exception("File not found");
                var QueryString = new Dictionary<string, string>()
                        {
                            {"message",content}
                        };

                return LineReq(Method.POST, "https://notify-api.line.me/api/notify", QueryString, file).Content;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public static string Message(string content, Tuple<string, byte[]> file)
        {
            try
            {
                var QueryString = new Dictionary<string, string>()
                        {
                            {"message",content}
                        };

                return LineReq(Method.POST, "https://notify-api.line.me/api/notify", QueryString, null, file).Content;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public static string RateLimit(Formatting format = Formatting.None)
        {
            try
            {
                IRestResponse result = LineReq(Method.GET, "https://notify-api.line.me/api/status");

                Dictionary<string, int> rawheader = new Dictionary<string, int>();
                foreach (var item in result.Headers)
                {
                    if (item.Name[0] == 'X')
                    {
                        rawheader.Add(item.Name, Convert.ToInt32(item.Value));
                    }
                }

                return JsonConvert.SerializeObject(rawheader, format).ToString();
            }
            catch (InvalidOperationException ex)
            {
                throw new InvalidOperationException(ex.Message);
            }
        }


        private static IRestResponse LineReq(Method method, string url, Dictionary<string, string> query = null, Tuple<string, string> pathfile = null, Tuple<string, byte[]> bytefile = null, Dictionary<string, string> paramUrl = null)
        {
            try
            {
                if (string.IsNullOrEmpty(LINE_TOKEN)) throw new NullReferenceException();
                var Client = new RestClient(url);
                Client.Timeout = 5000;
                var request = new RestRequest(method);
                request.AddHeader("Content-Type", "application/x-www-form-urlencoded");
                request.AddHeader("Authorization", $"Bearer {LINE_TOKEN}");

                if (pathfile != null)
                {
                    request.AlwaysMultipartFormData = true;
                    request.AddHeader("Content-Type", "multipart/form-data");
                    request.AddFile(pathfile.Item1, pathfile.Item2);
                }

                if (bytefile != null)
                {
                    request.AlwaysMultipartFormData = true;
                    request.AddHeader("Content-Type", "multipart/form-data");
                    request.AddFileBytes(bytefile.Item1, bytefile.Item2, "ex.png");
                }

                if (query != null)
                {
                    foreach (var items in query)
                    {
                        request.AddQueryParameter(items.Key.ToString(), items.Value.ToString());
                    }
                }

                if (paramUrl != null)
                {
                    foreach (var items in paramUrl)
                    {
                        request.AddParameter(items.Key.ToString(), items.Value.ToString());
                    }

                }

                IRestResponse response = Client.Execute(request);

                if (response.IsSuccessful)
                {
                    return response;
                }
                else
                {
                    throw new InvalidOperationException(response.Content);
                }

            }
            catch (NullReferenceException)
            {
                throw new Exception("Line Token IsNullOrEmpty!!");
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

        }
    }
}
