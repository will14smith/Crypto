using System;
using System.Collections.Generic;

namespace Crypto.Utils
{
    public struct Option<T>
    {
        public bool HasValue { get; }
        public T Value { get; }

        public Option(T value) { HasValue = true; Value = value; }

        public Option<TOut> Select<TOut>(Func<T, TOut> fn)
        {
            return HasValue ? new Option<TOut>(fn(Value)) : new Option<TOut>();
        }
        public TOut Map<TOut>(Func<T, TOut> some, Func<TOut> none)
        {
            return HasValue ? some(Value) : none();
        }
    }

    public static class Option
    {
        public static Option<T> Some<T>(T value)
        {
            return new Option<T>(value);
        }
        public static Option<T> None<T>()
        {
            return new Option<T>();
        }

        public static T OrElse<T>(this Option<T> opt, Func<T> func)
        {
            return opt.Map(x => x, func);
        }

        public static Option<T> SelectMany<T>(this Option<Option<T>> opt)
        {
            return opt.Select(x => x.Value);
        }
        public static Option<TOut> SelectMany<TIn, TOut>(this Option<TIn> opt, Func<TIn, Option<TOut>> some)
        {
            return opt.Select(some).Select(x => x.Value);
        }
    }

    public static class OptionExtensions
    {
        public static Option<TValue> TryGet<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> dict, TKey key)
        {
            TValue value;
            if (dict.TryGetValue(key, out value))
            {
                return Option.Some(value);
            }

            return Option.None<TValue>();
        }
    }

}
