using System;
using System.Collections.Generic;
using System.Data;
using System.Data.OleDb;
using System.Linq;

namespace GapzLib.DBHelper
{
    public class MSAccess
    {
        public static OleDbConnection static_Connection { get; set; }
        public static string dirPathDB { get; set; } = null;
        public OleDbConnection Connection { get; set; }

        private static MSAccess _instance = null;
        public static string DefaultConnectionString
        {
            get
            {
                return $"Provider = Microsoft.ACE.OLEDB.12.0; Data Source = { dirPathDB };";
            }
        }
        public static MSAccess Instance()
        {
            if (_instance == null)
                _instance = new MSAccess();
            return _instance;
        }

        public bool IsConnect()
        {

            if (Connection == null)
            {
                if (string.IsNullOrEmpty(dirPathDB)) throw new NullReferenceException("dirPathDB is null");
                string connstring = string.Format($"Provider = Microsoft.ACE.OLEDB.12.0;Data Source = {dirPathDB};");
                Connection = new OleDbConnection(connstring);
                Connection.Open();
            }
            else if (Connection.State == System.Data.ConnectionState.Closed)
            {

                if (string.IsNullOrEmpty(dirPathDB)) throw new NullReferenceException("dirPathDB is null");
                string connstring = string.Format($"Provider = Microsoft.ACE.OLEDB.12.0;Data Source ={dirPathDB}");
                Connection = new OleDbConnection(connstring);
                Connection.Open();

            }

            return true;
        }

        public void Close()
        {
            Connection.Close();
        }

        public static dynamic Query(string query)
        {
            dynamic cmd = null;
            var dbCon = MSAccess.Instance();
            if (query.Length > 0)
            {
                try
                {
                    if (dbCon.IsConnect())
                    {
                        cmd = new OleDbCommand(query, dbCon.Connection);
                        dynamic writer = cmd.ExecuteReader();
                        if (writer.Read())
                        {
                            return writer;
                        }

                    }
                    else { return "Database Not Working"; }
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return ex.Message;
                }
                finally
                {
                    dbCon.Close();
                }
            }
            else { return "Please Input Data"; }
            return cmd;

        }

        public static List<dynamic> CollectionQuery_All(string cmd, int index)
        {
            var dbCon = MSAccess.Instance();
            try
            {
                if (dbCon.IsConnect())
                {
                    List<dynamic> QueryResult = new List<dynamic>();
                    OleDbCommand cmdName = new OleDbCommand(cmd, dbCon.Connection);
                    OleDbDataReader reader = cmdName.ExecuteReader();
                    while (reader.Read())
                    {
                        QueryResult.Add(reader.GetValue(index));
                    }
                    reader.Close();
                    return QueryResult;
                }
                else { throw new InvalidOperationException("Database NotConnect"); }
            }
            catch
            {
                throw new InvalidCastException("variable not compatible with type ");
            }
            finally
            {
                dbCon.Close();
            }
        }

        public static DataTable ExecuteProcedure(string PROC_NAME, params object[] parameters)
        {
            try
            {
                if (parameters.Length % 2 != 0)
                    throw new ArgumentException("Wrong number of parameters sent to procedure. Expected an even number.");
                DataTable a = new DataTable();
                List<OleDbParameter> filters = new List<OleDbParameter>();

                string query = "EXEC " + PROC_NAME;

                bool first = true;
                for (int i = 0; i < parameters.Length; i += 2)
                {
                    filters.Add(new OleDbParameter(parameters[i] as string, parameters[i + 1]));
                    query += (first ? " " : ", ") + ((string)parameters[i]);
                    first = false;
                }

                a = Query(query, filters);
                return a;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static DataTable ExecuteQuery(string query, params object[] parameters)
        {
            try
            {
                if (parameters.Length % 2 != 0)
                    throw new ArgumentException("Wrong number of parameters sent to procedure. Expected an even number.");
                DataTable a = new DataTable();
                List<OleDbParameter> filters = new List<OleDbParameter>();

                for (int i = 0; i < parameters.Length; i += 2)
                    filters.Add(new OleDbParameter(parameters[i] as string, parameters[i + 1]));

                a = Query(query, filters);
                return a;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static int ExecuteNonQuery(string query, params object[] parameters)
        {
            try
            {
                if (parameters.Length % 2 != 0)
                    throw new ArgumentException("Wrong number of parameters sent to procedure. Expected an even number.");
                List<OleDbParameter> filters = new List<OleDbParameter>();

                for (int i = 0; i < parameters.Length; i += 2)
                    filters.Add(new OleDbParameter(parameters[i] as string, parameters[i + 1]));
                return NonQuery(query, filters);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static object ExecuteScalar(string query, params object[] parameters)
        {
            try
            {
                if (parameters.Length % 2 != 0)
                    throw new ArgumentException("Wrong number of parameters sent to query. Expected an even number.");
                List<OleDbParameter> filters = new List<OleDbParameter>();

                for (int i = 0; i < parameters.Length; i += 2)
                    filters.Add(new OleDbParameter(parameters[i] as string, parameters[i + 1]));
                return Scalar(query, filters);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #region Private Methods

        private static DataTable Query(string consulta, IList<OleDbParameter> parametros)
        {
            try
            {
                DataTable dt = new DataTable();
                OleDbConnection connection = new OleDbConnection(DefaultConnectionString);
                OleDbCommand command = new OleDbCommand();
                OleDbDataAdapter da;
                try
                {
                    command.Connection = connection;
                    command.CommandText = consulta;
                    if (parametros != null)
                    {
                        command.Parameters.AddRange(parametros.ToArray());
                    }
                    da = new OleDbDataAdapter(command);
                    da.Fill(dt);
                }
                finally
                {
                    if (connection != null)
                        connection.Close();
                }
                return dt;
            }
            catch (Exception)
            {
                throw;
            }

        }

        private static int NonQuery(string query, IList<OleDbParameter> parametros)
        {
            try
            {
                DataSet dt = new DataSet();
                OleDbConnection connection = new OleDbConnection(DefaultConnectionString);
                OleDbCommand command = new OleDbCommand();

                try
                {
                    connection.Open();
                    command.Connection = connection;
                    command.CommandText = query;
                    command.Parameters.AddRange(parametros.ToArray());
                    return command.ExecuteNonQuery();

                }
                finally
                {
                    if (connection != null)
                        connection.Close();
                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        private static object Scalar(string query, List<OleDbParameter> parametros)
        {
            try
            {
                DataSet dt = new DataSet();
                OleDbConnection connection = new OleDbConnection(DefaultConnectionString);
                OleDbCommand command = new OleDbCommand();

                try
                {
                    connection.Open();
                    command.Connection = connection;
                    command.CommandText = query;
                    command.Parameters.AddRange(parametros.ToArray());
                    return command.ExecuteScalar();

                }
                finally
                {
                    if (connection != null)
                        connection.Close();
                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #endregion
    }
}
