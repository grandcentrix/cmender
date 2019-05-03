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

#ifndef MENDER_TEST_COMMON_H
#define MENDER_TEST_COMMON_H

#include <mender/platform/types.h>
#include <mender/internal/compiler.h>
#include <setjmp.h>
#include <cmocka.h>

int mender_test_run_state(void);
int mender_test_run_installer(void);
int mender_test_run_stack(void);
int mender_test_run_utils(void);

int mender_run_all_tests(void);

#endif /* MENDER_TEST_COMMON_H */


