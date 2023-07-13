import {Body, Injectable, Post} from '@nestjs/common';
import {CreateUserDto} from "../users/dto/create-user.dto";
import {UsersService} from "../users/users.service";

@Injectable()
export class AuthService {
    constructor(private userService: UsersService) {
    }
    async login(userDto: CreateUserDto){
    }

    async registration(dto: CreateUserDto){
    }
}
