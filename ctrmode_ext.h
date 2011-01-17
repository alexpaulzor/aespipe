/*
 * Copyright 2010 Rapleaf
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CTRMODE_EXT_H
#define CTRMODE_EXT_H

extern void ctr_setup(int, void *, int, char *);
extern void ctr_finish();
extern void enqueue_data(unsigned char *, int);
extern int verbose;

#endif  //CTRMODE_EXT_H
