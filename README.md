## Extry: Turn Entry Into Exit

This program will hijack an ELF file's entry point so that, instead of the operations it would normally perform, it instead performs some user-defined operation:

	- Infinite: The hijacked program will loop forever (Not implemented).
	- Random: The hijacked program will jump to a random location (Not implemented).
	- Stop: The hijacked program will immediately stop.

### Building

#### 1 Requirements

Besides a modern C++ compiler and `cmake`, make sure that you have `libelf-dev` installed on your computer.

#### 2 Getting the Source

```
$ git clone https://github.com/hawkinsw/extry.git
```

To make the remaining installation steps easier, you may want to set an environment variable (e.g., `EXTRY_SOURCE_PATH`) with the location of your source. 

It's easy to do! From the same directory where you ran the `git clone`, do

```
$ cd extry
$ export EXTRY_SOURCE_PATH=`pwd`
```

#### 3 Initialize the Dependencies

After cloning, initialize the submodules:

```
$ cd ${EXTRY_SOURCE_PATH}
$ git submodule init
$ git submodule update --recursive
```

#### 4 Running `cmake`
Next, create a build directory. `cd` in to that build directory and
create/set a `EXTRY_BUILD_PATH` environment variable for use during the
rest of the build:

```
$ export EXTRY_BUILD_PATH=`pwd`
```

Now, from the `EXTRY_BUILD_PATH` directory, run `cmake`:

```
$ cmake ${EXTRY_SOURCE_PATH}
```

And, finally, just `make`:

```
$ make
```

### Running

From `EXTRY_BUILD_PATH`, you can run the hijacker:

```
$ ./extry
```
