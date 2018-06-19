package com.hierynomus.protocol.commons.concurrent;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class FutureWrapper<T extends U, U> implements Future<T> {

    private final Future<U> mDelegate;

    public FutureWrapper(Future<U> delegate) {
        mDelegate = delegate;
    }

    @Override
    public boolean cancel(boolean mayInterruptIfRunning) {
        return mDelegate.cancel(mayInterruptIfRunning);
    }

    @Override
    public boolean isCancelled() {
        return mDelegate.isCancelled();
    }

    @Override
    public boolean isDone() {
        return mDelegate.isDone();
    }

    @Override
    public T get() throws InterruptedException, ExecutionException {
        //noinspection unchecked
        return (T)mDelegate.get();
    }

    @Override
    public T get(long timeout, TimeUnit unit)
        throws InterruptedException, ExecutionException, TimeoutException {
        //noinspection unchecked
        return (T)mDelegate.get(timeout, unit);
    }
}
