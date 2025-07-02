/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { HttpClient } from '@angular/common/http'
import { Injectable } from '@angular/core'
import { environment } from 'src/environments/environment'
import { catchError, map } from 'rxjs/operators'
import { throwError } from 'rxjs'

@Injectable({
  providedIn: 'root'
})
export class SecurityQuestionService {
  private readonly hostServer = environment.hostServer
  private readonly host = this.hostServer + '/api/SecurityQuestions'

  constructor (private readonly http: HttpClient) { }

  find (params: any) {
    return this.http.get(this.host + '/', { params }).pipe(map((response: any) => response.data), catchError((err) => { throw err }))
  }

  findBy (email: string) {
    if (!localStorage.getItem('token')) {
      return throwError(() => new Error('Authentication required'))
    }
    return this.http.get(this.hostServer + '/' + 'rest/user/security-question?email=' + email).pipe(
      map((response: any) => response.question),
      catchError((error) => { throw error })
    )
  }
}
