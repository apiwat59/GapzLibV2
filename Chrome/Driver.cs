using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using OpenQA.Selenium.Support.UI;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace GapzLib.Chrome
{
    public class Driver
    {
        public ChromeDriver ChromeDriver { get; private set; }
        //public bool ShowConsole { get; set; }
        public Driver()
        {
            // Initialize driver options
            var options = new ChromeOptions();

            options.AddArgument("headless");
            //options.BinaryLocation = @"program\GoogleChromePortable64\GoogleChromePortable.exe";
            options.AddArgument("--silent");
            options.AddArgument("disable-infobars"); // disabling infobars
            options.AddArgument("--disable-extensions"); // disabling extensions
            options.AddArgument("--disable-gpu"); // applicable to windows os only
            options.AddArgument("--no-sandbox"); // Bypass OS security model

            var ServiceOption = ChromeDriverService.CreateDefaultService();
            ServiceOption.HideCommandPromptWindow = true;
            ServiceOption.SuppressInitialDiagnosticInformation = true;

            //options.AddArguments("--incognito", "--kiosk", "--disable-extensions");
            //options.AddExcludedArgument("enable-automation");
            //options.AddAdditionalCapability("useAutomationExtension", false);

            // Initialize new driver
            ChromeDriver = new ChromeDriver(ServiceOption, options);
        }

        public void GoTo(string url)
        {
            ChromeDriver.Navigate().GoToUrl(url);
        }

        public bool Type(string selector, string text)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                elem.SendKeys(text);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool SelectLastById(string id, string text)
        {
            try
            {
                var elem = ChromeDriver.FindElementsById(id).Last();
                var selectElement = new SelectElement(elem);
                selectElement.SelectByText(text);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool Tab(string selector)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                elem.SendKeys(Keys.Tab);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool Down(string selector)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                elem.SendKeys(Keys.Down);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool Enter(string selector)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                elem.SendKeys(Keys.Return);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool SelectValue(string selector, string value)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                var selectElement = new SelectElement(elem);
                selectElement.SelectByValue(value);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool SelectText(string selector, string text)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                var selectElement = new SelectElement(elem);
                selectElement.SelectByText(text);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool SelectIndex(string selector, int index)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                var selectElement = new SelectElement(elem);
                selectElement.SelectByIndex(index);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool DialogDismiss()
        {
            try
            {
                ChromeDriver.SwitchTo().Alert().Dismiss();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool Click(string selector)
        {
            try
            {
                var elem = ChromeDriver.FindElementByCssSelector(selector);
                elem.Click();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public bool ClickByXpatch(string selector)
        {
            try
            {
                var elem = ChromeDriver.FindElementByXPath(selector);
                elem.Click();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }
    }
}
