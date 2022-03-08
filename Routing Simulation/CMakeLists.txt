cmake_minimum_required(VERSION 2.8)
project(assignment2-rtp)

set(CMAKE_CXX_STANDARD 11)


#添加头文件搜索路径
include_directories(/usr/local/include)

#添加库文件搜索路径
link_directories(/usr/local/lib)

add_executable(agent
		common.h
		util.c
		agent.c)
target_link_libraries(agent)

add_executable(router
		common.h
		util.c
		router.c)
target_link_libraries(router)
