/*
 * Copyright (C) 2019 grandcentrix GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MENDER_LIST_H
#define MENDER_LIST_H

/*
 * we don't want to require users of the lib to have all our list functions
 * and macros, so just give them our data structure.
 */

struct mender_list_node {
    struct mender_list_node *prev;
    struct mender_list_node *next;
};

#endif /* MENDER_LIST_H */
