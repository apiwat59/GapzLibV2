using System;
using System.Collections.Generic;
using System.Text;

namespace GapzLib.Chrome
{
    public static class Core
    {
        public static Driver Driver { get; private set; }

        public static void InitializeDriver()
        {
            // Initialize new driver
            Driver = new Driver();
        }

    }
}
