using System;
using System.Runtime.Versioning;

namespace LocalPolicyLibrary
{
  
    public class GroupPolicyException : Exception
    {
        internal GroupPolicyException(string message)
            : base(message) { }
    }
}
