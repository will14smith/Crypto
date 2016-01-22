using System;
using System.Runtime.CompilerServices;
using System.Security;
using JetBrains.Annotations;

namespace Crypto.Utils
{
    public static class SecurityAssert
    {
        [AssertionMethod]
        public static void NotNull<T>([AssertionCondition(AssertionConditionType.IS_NOT_NULL)] T obj, [CallerMemberName] string callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string callerFile = null)
        {
            InnerSAssert(obj != null, callerName, callerLine, callerFile);
        }


        [AssertionMethod]
        public static void SAssert([AssertionCondition(AssertionConditionType.IS_TRUE)] bool condition, [CallerMemberName] string callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string callerFile = null)
        {
            InnerSAssert(condition, callerName, callerLine, callerFile);
        }

        public static void SAssert(Func<bool> condition, [CallerMemberName] string callerName = null, [CallerLineNumber] int callerLine = 0, [CallerFilePath] string callerFile = null)
        {
            InnerSAssert(condition(), callerName, callerLine, callerFile);
        }

        private static void InnerSAssert(bool condition, string callerName, int callerLine, string callerFile)
        {
            if (condition) return;

            throw new SecurityException($"Failed security assertion in '{callerName}' - {callerFile}:{callerLine}");
        }
    }
}
