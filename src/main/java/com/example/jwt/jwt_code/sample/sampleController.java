package com.example.jwt.jwt_code.sample;

import java.util.HashMap;

import com.example.jwt.jwt_code.config.jwt.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class sampleController {

  @Autowired
  private JwtTokenUtil jwtTokenUtil;
  
  @RequestMapping(value = "/jwt/get/token")
  public String getToken(@RequestParam String userId , @RequestParam String userNm ) throws Exception {
    HashMap<String, Object> param = new HashMap<>();
    param.put("userId" , userId );
    param.put("userNm" , userNm );
    String token = jwtTokenUtil.generateTokenForUser(param); //make Token
    return token;
    
  };

  /*
    프론트는 return 받은 token 값을 header의 Authorization 담아 요청
  */
  @RequestMapping(value = "/jwt/set/token")
  public String getUserId(@RequestHeader String Authorization) throws Exception {
    String userId = jwtTokenUtil.getUserIdFromToken(Authorization);
    String userNm = jwtTokenUtil.getUserNmFromToken(Authorization);
    return "UserId : " + userId  + ", UserNm : "+userNm ;
  };
  

}
